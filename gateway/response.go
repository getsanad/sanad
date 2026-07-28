package gateway

import (
	"context"
	"errors"
	"log"
	"net/http"
)

// ResponseInspector examines an upstream RESPONSE before any of it reaches the client, and
// returns an error to refuse it.
//
// It exists for the one class of check that cannot be made on the request: MCP tool definitions
// travel in a tools/list response, so tool-definition drift (PRD SEC-3, tooldefs) is invisible
// to every request-path stage. The seam is deliberately narrow — one optional hook, nil by
// default — because the response path is where streaming lives, and the gateway's contract is
// that an SSE stream is forwarded byte-for-byte and flushed per write (Registry.Register sets
// FlushInterval = -1).
//
// AN INSPECTOR MUST NOT BUFFER A STREAM. It is handed the response with its body unread and may
// read it, but a body it reads it must put back, and a body it cannot afford to hold it must
// wrap in a pass-through reader rather than drain. The gateway does not police this; what it
// guarantees is that an inspector is called at all only for responses the gateway is proxying,
// and that returning nil leaves the response exactly as the upstream sent it.
//
// Returning an error wrapping ErrResponseRefused answers the client 403. Any other error is
// treated as an upstream failure and answered 502.
type ResponseInspector func(req *Request, resp *http.Response) error

// ErrResponseRefused marks a response an inspector rejected on policy grounds — as opposed to
// one that failed in transit. Wrapping it is what turns the refusal into a 403 ("we decided
// against this") rather than the 502 a broken upstream gets, so an operator reading access logs
// can tell an enforcement decision from an outage.
var ErrResponseRefused = errors.New("gateway: upstream response refused")

// inspectKey carries the per-request inspection hook to the reverse proxy's ModifyResponse.
// It goes through the context because the proxy is built once per server in Registry.Register,
// while the hook is bound to the in-flight Request the pipeline just decided — and
// httputil.ReverseProxy hands ModifyResponse only the response, whose .Request is the outbound
// clone carrying this context.
type inspectKey struct{}

type inspectHook func(resp *http.Response) error

// withInspector returns r carrying the hook for its own response.
func withInspector(r *http.Request, hook inspectHook) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), inspectKey{}, hook))
}

// inspectResponse is the ModifyResponse every registered server's proxy runs. With no hook on
// the request — the default, and every request when the gateway has no inspector — it is a
// single failed type assertion and a return.
func inspectResponse(resp *http.Response) error {
	if resp == nil || resp.Request == nil {
		return nil
	}
	hook, _ := resp.Request.Context().Value(inspectKey{}).(inspectHook)
	if hook == nil {
		return nil
	}
	return hook(resp)
}

// proxyError answers a proxying failure. It splits a refusal by an inspector (403: the gateway
// decided against forwarding this) from everything else (502: the upstream failed), which the
// default handler cannot do because it treats every ModifyResponse error as a bad gateway.
func proxyError(w http.ResponseWriter, _ *http.Request, err error) {
	if errors.Is(err, ErrResponseRefused) {
		http.Error(w, "denied", http.StatusForbidden)
		return
	}
	log.Printf("gateway: proxy error: %v", err)
	w.WriteHeader(http.StatusBadGateway)
}
