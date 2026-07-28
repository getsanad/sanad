package gateway

import (
	"net/http"

	"github.com/getsanad/sanad/internal/mcprpc"
)

// DefaultMaxRequestBody bounds how much of a request body the gateway will hold in memory
// (1 MiB). See mcprpc.DefaultMaxBody for why there is a cap and no unlimited setting.
const DefaultMaxRequestBody = mcprpc.DefaultMaxBody

// RPCCall is one JSON-RPC message the gateway parsed out of a request body, reduced to what
// a decision needs (one per element for a batch). It is an ALIAS, not a wrapper: the parsing
// lives in internal/mcprpc so the resource-server side (verify.EnforceScope) enforces the
// invoked tool against exactly the same reading of the body the gateway authorized, rather
// than a second implementation that could disagree with it.
type RPCCall = mcprpc.Call

// parseRPC extracts the JSON-RPC calls a request body contains. See mcprpc.Parse for the
// deliberately asymmetric posture on unreadable bodies vs. a tools/call naming no tool.
func parseRPC(body []byte) ([]RPCCall, error) { return mcprpc.Parse(body) }

// bufferRequestBody reads the body once, under a cap, and puts it back so the reverse proxy
// still forwards it byte-for-byte.
func bufferRequestBody(w http.ResponseWriter, r *http.Request, max int64) ([]byte, error) {
	return mcprpc.BufferBody(w, r, max)
}

// hasRequestBody reports whether a request carries a body worth buffering (POST only).
func hasRequestBody(r *http.Request) bool { return mcprpc.HasBody(r) }

// errBodyTooLarge marks a body that hit the cap, so the caller can answer 413 rather than
// the 400 a truncated or aborted read gets.
var errBodyTooLarge = mcprpc.ErrBodyTooLarge
