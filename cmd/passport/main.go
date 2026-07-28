// Command passport is the agent-side tool. It lets an agent talk to protected MCP servers
// through the gateway without any code changes:
//
//	passport keygen --out agent.key
//	passport proxy --gateway https://gw.example.com --key agent.key --credential cred.json
//
// `proxy` runs a local sidecar: point your agent's MCP client at it (e.g.
// http://127.0.0.1:7070/servers/<id>/...) and it injects the principal token, the workload
// credential + proof of possession, and an optional delegation chain, then forwards to the
// gateway. The agent never has to build any of those headers itself.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/getsanad/sanad/delegation"
	"github.com/getsanad/sanad/workload"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "keygen":
		keygen(os.Args[2:])
	case "enroll":
		enroll(os.Args[2:])
	case "proxy":
		runProxy(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `passport — Sanad agent-side tool

Usage:
  passport keygen [--out agent.key]
      Generate an Ed25519 instance key. Give its public key to your operator to
      obtain a workload credential.

  passport enroll --authority URL --token TOK [--key agent.key --out cred.json]
      Generate (or reuse) an instance key, present the bootstrap token to the
      authority, and save the issued workload credential.

  passport proxy --gateway URL --key FILE --credential FILE [options]
      Run a local sidecar. Point your agent's MCP client at it; it injects the
      principal token, workload credential + proof, and delegation chain, then
      forwards to the gateway.

      --listen ADDR       local address (default 127.0.0.1:7070)
      --token-env VAR     env var with the principal bearer token (default PASSPORT_PRINCIPAL_TOKEN)
      --token-file FILE   file with the principal bearer token (overrides --token-env)
      --delegation FILE   delegation chain JSON (gateways with delegation enabled
                          require one unless PASSPORT_ALLOW_DIRECT_PRINCIPAL=1)`)
	os.Exit(2)
}

func keygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "agent.key", "file to write the instance private key to")
	_ = fs.Parse(args)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("keygen: %v", err)
	}
	if err := os.WriteFile(*out, []byte(base64.RawURLEncoding.EncodeToString(priv)), 0o600); err != nil {
		log.Fatalf("keygen: %v", err)
	}
	fmt.Printf("instance key written to %s (keep it secret)\n", *out)
	fmt.Printf("public key (base64url): %s\n", base64.RawURLEncoding.EncodeToString(pub))
}

func enroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	authority := fs.String("authority", "", "authority base URL (required)")
	token := fs.String("token", "", "bootstrap attestation token (required)")
	keyFile := fs.String("key", "agent.key", "instance private key file (generated if missing)")
	out := fs.String("out", "cred.json", "file to write the issued workload credential to")
	_ = fs.Parse(args)

	if *authority == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "enroll: --authority and --token are required")
		os.Exit(2)
	}

	_, pub, err := loadOrGenKey(*keyFile)
	if err != nil {
		log.Fatalf("enroll: %v", err)
	}
	// The bootstrap token stays here: what goes on the wire is a MAC over the authority's
	// nonce and this public key, so it enrolls this key once and nothing else.
	cred, err := workload.Enroll(context.Background(), nil, *authority, pub,
		func(nonce []byte, pub ed25519.PublicKey) ([]byte, error) {
			return workload.BootstrapEvidence(*token, nonce, pub), nil
		})
	if err != nil {
		log.Fatalf("enroll: %v", err)
	}
	b, _ := json.MarshalIndent(cred, "", "  ")
	if err := os.WriteFile(*out, b, 0o600); err != nil {
		log.Fatalf("enroll: %v", err)
	}
	fmt.Printf("enrolled as %q\ncredential -> %s (expires %s)\ninstance key -> %s\nnow run: passport proxy --gateway URL --key %s --credential %s\n",
		cred.AgentID, *out, cred.NotAfter.Format(time.RFC3339), *keyFile, *keyFile, *out)
}

// loadOrGenKey loads the instance key from path, or generates and writes one if absent.
func loadOrGenKey(path string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		raw, derr := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(b)))
		if derr != nil || len(raw) != ed25519.PrivateKeySize {
			return nil, nil, fmt.Errorf("bad instance key in %s", path)
		}
		priv := ed25519.PrivateKey(raw)
		return priv, priv.Public().(ed25519.PublicKey), nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(path, []byte(base64.RawURLEncoding.EncodeToString(priv)), 0o600); err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

func runProxy(args []string) {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	gatewayURL := fs.String("gateway", "", "gateway base URL (required)")
	listen := fs.String("listen", "127.0.0.1:7070", "local listen address")
	keyFile := fs.String("key", "", "instance private key file from `keygen` (required)")
	credFile := fs.String("credential", "", "workload credential JSON file (required)")
	tokenEnv := fs.String("token-env", "PASSPORT_PRINCIPAL_TOKEN", "env var holding the principal bearer token")
	tokenFile := fs.String("token-file", "", "file holding the principal bearer token (overrides --token-env)")
	delegationFile := fs.String("delegation", "", "delegation chain JSON file (required by gateways with delegation enabled)")
	_ = fs.Parse(args)

	if *gatewayURL == "" || *keyFile == "" || *credFile == "" {
		fmt.Fprintln(os.Stderr, "proxy: --gateway, --key and --credential are required")
		os.Exit(2)
	}

	key, err := loadInstanceKey(*keyFile)
	if err != nil {
		log.Fatalf("proxy: %v", err)
	}
	credHeader, err := loadCredHeader(*credFile)
	if err != nil {
		log.Fatalf("proxy: %v", err)
	}
	var chainHeader string
	if *delegationFile != "" {
		if chainHeader, err = loadChainHeader(*delegationFile); err != nil {
			log.Fatalf("proxy: %v", err)
		}
	}

	h, err := newSidecar(sidecarConfig{
		gatewayURL:  *gatewayURL,
		instanceKey: key,
		credHeader:  credHeader,
		chainHeader: chainHeader,
		token:       tokenSource(*tokenFile, *tokenEnv),
	})
	if err != nil {
		log.Fatalf("proxy: %v", err)
	}
	log.Printf("passport sidecar on %s -> %s", *listen, *gatewayURL)
	if err := http.ListenAndServe(*listen, h); err != nil {
		log.Fatalf("proxy: %v", err)
	}
}

type sidecarConfig struct {
	gatewayURL  string
	instanceKey ed25519.PrivateKey
	credHeader  string
	chainHeader string
	token       func() (string, error)
}

// newSidecar returns the reverse-proxy handler that injects passport credentials onto each
// request before forwarding to the gateway.
func newSidecar(cfg sidecarConfig) (http.Handler, error) {
	target, err := url.Parse(cfg.gatewayURL)
	if err != nil {
		return nil, fmt.Errorf("bad gateway URL: %w", err)
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	base := rp.Director
	rp.Director = func(r *http.Request) {
		base(r)
		tok, err := cfg.token()
		if err != nil {
			// Leave credentials off; the gateway will deny (fail closed).
			return
		}
		r.Header.Set("Authorization", "Bearer "+tok)
		r.Header.Set(workload.HeaderCredential, cfg.credHeader)
		r.Header.Set(workload.HeaderProof, workload.Proof(cfg.instanceKey, tok))
		if cfg.chainHeader != "" {
			r.Header.Set(delegation.HeaderDelegation, cfg.chainHeader)
		}
	}
	return rp, nil
}

func loadInstanceKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("bad instance key encoding: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("instance key has wrong length")
	}
	return ed25519.PrivateKey(raw), nil
}

func loadCredHeader(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var c workload.Credential
	if err := json.Unmarshal(b, &c); err != nil {
		return "", fmt.Errorf("bad credential file: %w", err)
	}
	return workload.EncodeCredential(c)
}

func loadChainHeader(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var c delegation.Chain
	if err := json.Unmarshal(b, &c); err != nil {
		return "", fmt.Errorf("bad delegation file: %w", err)
	}
	return delegation.EncodeChain(c)
}

func tokenSource(file, env string) func() (string, error) {
	return func() (string, error) {
		if file != "" {
			b, err := os.ReadFile(file)
			if err != nil {
				return "", err
			}
			return strings.TrimSpace(string(b)), nil
		}
		t := os.Getenv(env)
		if t == "" {
			return "", fmt.Errorf("no principal token in $%s", env)
		}
		return t, nil
	}
}
