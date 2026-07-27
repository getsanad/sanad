// Command echomcp is a stand-in "protected MCP server" for local validation. It is NOT part
// of the product — it exists so the docker-compose stack has something behind the gateway.
// It echoes back what it received (notably the Authorization header) as JSON, which lets you
// SEE that the gateway forwarded a freshly-minted passport and never the caller's own
// credential (token isolation, FR-8).
//
//	ADDR   listen address (default :9090)
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":9090"
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		received := "(none)"
		if tok, ok := strings.CutPrefix(auth, "Bearer "); ok {
			received = tok
		}
		out := map[string]any{
			"upstream":          "echomcp",
			"method":            r.Method,
			"path":              r.URL.Path,
			"received_passport": received, // the minted passport JWT the gateway issued
			"tools":             []string{"read", "list"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	log.Printf("echomcp (demo upstream) listening on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("echomcp: %v", err)
	}
}
