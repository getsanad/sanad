package gateway

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// inspected stands a gateway with a response inspector in front of an upstream.
func inspected(t *testing.T, inspect ResponseInspector, upstream http.Handler) *httptest.Server {
	t.Helper()
	up := httptest.NewServer(upstream)
	t.Cleanup(up.Close)

	reg := NewRegistry()
	if err := reg.Register(&Server{ID: "demo", Upstream: mustURL(t, up.URL)}); err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(&Gateway{
		Registry: reg,
		Pipeline: Pipeline{Stages: []Stage{stubMint()}},
		Inspect:  inspect,
	})
	t.Cleanup(front.Close)
	return front
}

// TestNoInspectorLeavesTheResponsePathAlone: the seam is nil by default, and a gateway that
// sets no inspector must proxy exactly as it did before it existed.
func TestNoInspectorLeavesTheResponsePathAlone(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Upstream", "yes")
		_, _ = io.WriteString(w, "upstream body")
	})
	front := inspected(t, nil, upstream)

	resp, err := http.Get(front.URL + "/servers/demo/mcp")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "upstream body" || resp.Header.Get("X-Upstream") != "yes" {
		t.Fatalf("got %d %q (X-Upstream=%q)", resp.StatusCode, body, resp.Header.Get("X-Upstream"))
	}
}

// TestInspectorSeesTheDecidedRequest: an inspector needs the identity-enriched Request the
// pipeline just decided, not only the response — otherwise a security event it raises cannot
// be attributed to anyone.
func TestInspectorSeesTheDecidedRequest(t *testing.T) {
	var gotServer, gotPassport string
	var gotStatus int
	front := inspected(t, func(req *Request, resp *http.Response) error {
		gotServer = req.Server
		gotStatus = resp.StatusCode
		if req.Passport != nil {
			gotPassport = req.Passport.ID
		}
		return nil
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	resp, err := http.Get(front.URL + "/servers/demo/mcp")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotServer != "demo" || gotStatus != http.StatusTeapot || gotPassport != "passport-1" {
		t.Fatalf("inspector saw server=%q status=%d passport=%q", gotServer, gotStatus, gotPassport)
	}
}

// TestRefusedResponseAnswers403AndWithholdsTheBody: refusing must be preventive — not one byte
// of the upstream's response may reach the client — and it must be distinguishable in the
// access log from an upstream that simply broke.
func TestRefusedResponseAnswers403AndWithholdsTheBody(t *testing.T) {
	front := inspected(t, func(_ *Request, _ *http.Response) error {
		return fmt.Errorf("%w: pinned definitions do not match", ErrResponseRefused)
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Leak", "secret")
		_, _ = io.WriteString(w, "poisoned tool definitions")
	}))

	resp, err := http.Get(front.URL + "/servers/demo/mcp")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a refusal is a denial, not an upstream failure: got %d", resp.StatusCode)
	}
	if strings.Contains(string(body), "poisoned") || resp.Header.Get("X-Leak") != "" {
		t.Fatalf("the refused response leaked: body=%q header=%q", body, resp.Header.Get("X-Leak"))
	}
}

// TestOtherInspectorErrorsAre502: only an ErrResponseRefused is an enforcement decision;
// anything else the inspector reports is a failure to complete the proxying.
func TestOtherInspectorErrorsAre502(t *testing.T) {
	front := inspected(t, func(_ *Request, _ *http.Response) error {
		return fmt.Errorf("reading the response: connection reset")
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	resp, err := http.Get(front.URL + "/servers/demo/mcp")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("got %d, want 502", resp.StatusCode)
	}
}

// TestInspectorDoesNotBreakSSEStreaming is the guard rail on the whole seam. The gateway sets
// FlushInterval = -1 so an SSE stream is delivered event by event; an inspector that is merely
// PRESENT must not change that, and an inspector that wraps the body in a pass-through reader
// must not change it either.
func TestInspectorDoesNotBreakSSEStreaming(t *testing.T) {
	for _, tc := range []struct {
		name    string
		inspect ResponseInspector
	}{
		{"inspector present but passive", func(*Request, *http.Response) error { return nil }},
		{"inspector wraps the body", func(_ *Request, resp *http.Response) error {
			resp.Body = passthrough{resp.Body}
			return nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			release := make(chan struct{})
			front := inspected(t, tc.inspect, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "event: message\ndata: first\n\n")
				w.(http.Flusher).Flush()
				<-release // hold the stream open: the first event must already have been delivered
				_, _ = io.WriteString(w, "event: message\ndata: second\n\n")
				w.(http.Flusher).Flush()
			}))

			req, _ := http.NewRequest(http.MethodGet, front.URL+"/servers/demo/mcp", nil)
			req.Header.Set("Accept", "text/event-stream")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				close(release)
				resp.Body.Close()
			}()

			lines := bufio.NewReader(resp.Body)
			read := make(chan string, 1)
			go func() {
				for {
					line, err := lines.ReadString('\n')
					if err != nil {
						return
					}
					if data, ok := strings.CutPrefix(line, "data: "); ok {
						read <- strings.TrimSpace(data)
						return
					}
				}
			}()
			select {
			case got := <-read:
				if got != "first" {
					t.Fatalf("first SSE event = %q, want %q", got, "first")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("no SSE event arrived while the upstream stream was still open: the inspector buffered it")
			}
		})
	}
}

// passthrough is the shape an inspector must use on a streaming body: every byte handed on in
// the Read that produced it.
type passthrough struct{ src io.ReadCloser }

func (p passthrough) Read(b []byte) (int, error) { return p.src.Read(b) }
func (p passthrough) Close() error               { return p.src.Close() }
