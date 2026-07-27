// Command admin serves the Sanad control-plane API (P1-10): register/disable
// principals, agents, and protected servers, and drive the kill-switch.
//
// Configuration (env):
//
//	PASSPORT_ADMIN_ADDR          listen address (default :8081)
//	PASSPORT_ADMIN_TOKEN         bearer token required on every request (empty = open, dev only)
//	PASSPORT_REVOCATION_DSN      Postgres DSN for a shared kill-switch (empty = in-memory)
//
// When PASSPORT_REVOCATION_DSN is set, admin writes revocations to the same Postgres source
// the gateway reads (ADR-004), so flipping the kill-switch here reaches every gateway
// replica. The principal/agent registry is still in-memory in this standalone process; a
// full deployment would share it too, but the kill-switch is the safety-critical piece.
package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/getsanad/sanad/admin"
	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/revoke"
	pgrevoke "github.com/getsanad/sanad/revoke/postgres"

	_ "github.com/jackc/pgx/v5/stdlib" // register the "pgx" database/sql driver
)

func main() {
	kill, err := buildKillSwitch()
	if err != nil {
		log.Fatalf("admin: kill-switch: %v", err)
	}
	svc := admin.NewService(gateway.NewRegistry(), kill)

	token := os.Getenv("PASSPORT_ADMIN_TOKEN")
	if token == "" {
		log.Print("PASSPORT_ADMIN_TOKEN unset: admin API is UNAUTHENTICATED (development only)")
	}

	addr := os.Getenv("PASSPORT_ADMIN_ADDR")
	if addr == "" {
		addr = ":8081"
	}
	log.Printf("sanad admin API listening on %s", addr)
	if err := http.ListenAndServe(addr, admin.NewHandler(svc, token)); err != nil {
		log.Fatalf("admin: %v", err)
	}
}

// buildKillSwitch returns the control-plane kill-switch. With PASSPORT_REVOCATION_DSN it
// writes through to the shared Postgres source the gateway reads; otherwise it is a local
// in-memory store (this process only). A failed durable write is logged loudly rather than
// silently dropped — on a kill-switch, an unnoticed failed revoke is a security incident.
func buildKillSwitch() (revoke.Store, error) {
	dsn := os.Getenv("PASSPORT_REVOCATION_DSN")
	if dsn == "" {
		log.Print("kill-switch: in-memory (set PASSPORT_REVOCATION_DSN to share it with the gateway)")
		return revoke.NewMemStore(), nil
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	src, err := pgrevoke.New(db)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := src.Migrate(ctx); err != nil {
		return nil, err
	}
	log.Print("kill-switch: shared Postgres source")
	return revoke.NewSyncStore(src, func(op, id string, err error) {
		log.Printf("ALERT: kill-switch %s %q FAILED against durable store: %v", op, id, err)
	}), nil
}
