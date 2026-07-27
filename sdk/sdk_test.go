package sdk

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCallShapesRequest(t *testing.T) {
	var gotPath, gotAuth, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotMethod = r.Method
		_, _ = io.WriteString(w, "pong")
	}))
	defer srv.Close()

	c := New(srv.URL, func(context.Context) (string, error) { return "idp-token", nil })
	resp, err := c.Call(context.Background(), "demo", http.MethodPost, "tools/call", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	defer resp.Body.Close()

	if gotMethod != http.MethodPost {
		t.Fatalf("method = %s, want POST", gotMethod)
	}
	if gotPath != "/servers/demo/tools/call" {
		t.Fatalf("path = %s, want /servers/demo/tools/call", gotPath)
	}
	if gotAuth != "Bearer idp-token" {
		t.Fatalf("auth = %q, want Bearer idp-token", gotAuth)
	}
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "pong" {
		t.Fatalf("body = %q, want pong", b)
	}
}

func TestCallTokenSourceError(t *testing.T) {
	c := New("http://gateway.invalid", func(context.Context) (string, error) {
		return "", errors.New("no token")
	})
	if _, err := c.Call(context.Background(), "demo", http.MethodGet, "/x", nil); err == nil {
		t.Fatal("token source error must propagate (and no request sent)")
	}
}

func TestCallRequiresTokenSource(t *testing.T) {
	c := New("http://gateway.invalid", nil)
	if _, err := c.Call(context.Background(), "demo", http.MethodGet, "/x", nil); err == nil {
		t.Fatal("missing token source must error")
	}
}
