package sdk

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// capture records what the gateway-side server saw, so we can assert request shaping.
type capture struct {
	path   string
	method string
	auth   string
	body   string
	status int
}

func newCaptureServer(t *testing.T, respStatus int, respBody string) (*httptest.Server, *capture) {
	t.Helper()
	cap := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.path = r.URL.Path
		cap.method = r.Method
		cap.auth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		cap.body = string(b)
		cap.status = respStatus
		if respStatus != 0 {
			w.WriteHeader(respStatus)
		}
		_, _ = io.WriteString(w, respBody)
	}))
	t.Cleanup(srv.Close)
	return srv, cap
}

func staticToken(tok string) TokenSource {
	return func(context.Context) (string, error) { return tok, nil }
}

func TestCallPathShaping(t *testing.T) {
	cases := []struct {
		name     string
		server   string
		path     string
		wantPath string
	}{
		{"with leading slash", "demo", "/tools/list", "/servers/demo/tools/list"},
		{"without leading slash normalized", "demo", "tools/call", "/servers/demo/tools/call"},
		{"empty path becomes root slash", "demo", "", "/servers/demo/"},
		{"root path", "demo", "/", "/servers/demo/"},
		{"nested path preserved", "srv-1", "a/b/c", "/servers/srv-1/a/b/c"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, cap := newCaptureServer(t, http.StatusOK, "ok")
			c := New(srv.URL, staticToken("tk"))
			resp, err := c.Call(context.Background(), tc.server, http.MethodGet, tc.path, nil)
			if err != nil {
				t.Fatalf("call: %v", err)
			}
			resp.Body.Close()
			if cap.path != tc.wantPath {
				t.Fatalf("path = %q, want %q", cap.path, tc.wantPath)
			}
		})
	}
}

func TestNewTrimsTrailingSlashFromGatewayURL(t *testing.T) {
	srv, cap := newCaptureServer(t, http.StatusOK, "ok")
	// Add a trailing slash to the gateway URL; the client must trim it so the path is not
	// doubled (e.g. //servers/demo/...).
	c := New(srv.URL+"/", staticToken("tk"))
	resp, err := c.Call(context.Background(), "demo", http.MethodGet, "/x", nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	resp.Body.Close()
	if cap.path != "/servers/demo/x" {
		t.Fatalf("path = %q, want /servers/demo/x (no doubled slash)", cap.path)
	}
}

func TestNewTrimsMultipleTrailingSlashes(t *testing.T) {
	srv, cap := newCaptureServer(t, http.StatusOK, "ok")
	c := New(srv.URL+"///", staticToken("tk"))
	resp, err := c.Call(context.Background(), "demo", http.MethodGet, "/x", nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	resp.Body.Close()
	if cap.path != "/servers/demo/x" {
		t.Fatalf("path = %q, want /servers/demo/x", cap.path)
	}
}

func TestCallMethodAndBodyPassthrough(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		srv, cap := newCaptureServer(t, http.StatusOK, "ok")
		c := New(srv.URL, staticToken("tk"))
		const payload = `{"jsonrpc":"2.0","method":"tools/call"}`
		resp, err := c.Call(context.Background(), "demo", method, "/rpc", strings.NewReader(payload))
		if err != nil {
			t.Fatalf("%s: call: %v", method, err)
		}
		resp.Body.Close()
		if cap.method != method {
			t.Fatalf("method = %s, want %s", cap.method, method)
		}
		if cap.body != payload {
			t.Fatalf("%s body = %q, want %q", method, cap.body, payload)
		}
	}
}

func TestCallAttachesBearerToken(t *testing.T) {
	srv, cap := newCaptureServer(t, http.StatusOK, "ok")
	c := New(srv.URL, staticToken("idp-xyz"))
	resp, err := c.Call(context.Background(), "demo", http.MethodGet, "/x", nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	resp.Body.Close()
	if cap.auth != "Bearer idp-xyz" {
		t.Fatalf("auth = %q, want Bearer idp-xyz", cap.auth)
	}
}

func TestCallNon2xxIsReturnedNotErrored(t *testing.T) {
	// A 4xx/5xx from upstream is a valid HTTP response, not a transport error; the client
	// must return it with a nil error so callers can inspect the status.
	for _, code := range []int{http.StatusForbidden, http.StatusUnauthorized, http.StatusInternalServerError, http.StatusBadGateway} {
		srv, _ := newCaptureServer(t, code, "denied")
		c := New(srv.URL, staticToken("tk"))
		resp, err := c.Call(context.Background(), "demo", http.MethodGet, "/x", nil)
		if err != nil {
			t.Fatalf("code %d: expected nil error, got %v", code, err)
		}
		if resp.StatusCode != code {
			t.Fatalf("status = %d, want %d", resp.StatusCode, code)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != "denied" {
			t.Fatalf("body = %q, want denied", b)
		}
	}
}

func TestCallTokenSourceErrorSendsNoRequest(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hit = true
	}))
	defer srv.Close()
	c := New(srv.URL, func(context.Context) (string, error) {
		return "", io.ErrUnexpectedEOF
	})
	if _, err := c.Call(context.Background(), "demo", http.MethodGet, "/x", nil); err == nil {
		t.Fatal("token-source error must propagate")
	}
	if hit {
		t.Fatal("no HTTP request should be sent when the token source fails")
	}
}

func TestCallNilTokenSourceSendsNoRequest(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hit = true
	}))
	defer srv.Close()
	c := New(srv.URL, nil)
	if _, err := c.Call(context.Background(), "demo", http.MethodGet, "/x", nil); err == nil {
		t.Fatal("nil token source must error")
	}
	if hit {
		t.Fatal("no HTTP request should be sent without a token source")
	}
}

func TestWithHTTPClientIsUsed(t *testing.T) {
	srv, _ := newCaptureServer(t, http.StatusTeapot, "")
	custom := &http.Client{}
	c := New(srv.URL, staticToken("tk"), WithHTTPClient(custom))
	resp, err := c.Call(context.Background(), "demo", http.MethodGet, "/x", nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("status = %d, want 418 (custom client should reach the server)", resp.StatusCode)
	}
}

func TestCallInvalidMethodErrors(t *testing.T) {
	// An illegal method string makes http.NewRequestWithContext fail before any network IO.
	c := New("http://gateway.invalid", staticToken("tk"))
	if _, err := c.Call(context.Background(), "demo", "BAD METHOD", "/x", nil); err == nil {
		t.Fatal("an invalid method must surface the request-construction error")
	}
}
