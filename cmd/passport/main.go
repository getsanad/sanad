// Command passport is the agent-side tool. It lets an agent talk to protected MCP servers
// through the gateway without any code changes:
//
//	passport keygen --out agent.key
//	passport proxy --gateway https://gw.example.com --key agent.key --credential cred.json
//
// `proxy` runs a local sidecar: point your agent's MCP client at it (e.g.
// http://127.0.0.1:7070/servers/<id>/...) and it injects the principal token, the workload
// credential + proof of possession, a principal holder proof when a principal key is
// configured (--principal-key, required by gateways in VC mode), and an optional delegation
// chain, then forwards to the gateway. The agent never has to build any of those headers.
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
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/getsanad/sanad/delegation"
	"github.com/getsanad/sanad/internal/mcprpc"
	"github.com/getsanad/sanad/vc"
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

  passport enroll --authority URL [--token-file FILE | --token-env VAR]
                  [--key agent.key --out cred.json]
      Generate (or reuse) an instance key, present the bootstrap token to the
      authority, and save the issued workload credential. Bootstrap tokens are
      single-use and expiring: enroll once per token, at startup.

      --token-file FILE   file holding the bootstrap token ("-" reads stdin)
      --token-env VAR     env var holding it instead (default PASSPORT_BOOTSTRAP_TOKEN)

      There is no --token flag: an argument is visible to every process on the
      host (ps, /proc/<pid>/cmdline) and is written to your shell history.

  passport proxy --gateway URL --key FILE --credential FILE [options]
      Run a local sidecar. Point your agent's MCP client at it; it injects the
      principal token, workload credential + proof, and delegation chain, then
      forwards to the gateway.

      --listen ADDR       local address (default 127.0.0.1:7070)
      --token-env VAR     env var with the principal bearer token (default PASSPORT_PRINCIPAL_TOKEN)
      --token-file FILE   file with the principal bearer token (overrides --token-env)
      --principal-key FILE  the principal's did:key private key. REQUIRED by gateways in
                          VC mode (PASSPORT_PRINCIPAL_MODE=vc): the credential is not a
                          bearer token, so each request carries a proof of possession of
                          this key. Omit it in OIDC mode, where there is no such key.
      --delegation FILE   delegation chain JSON (gateways with delegation enabled
                          require one unless PASSPORT_ALLOW_DIRECT_PRINCIPAL=1)
      --max-body BYTES    request body buffered to bind the proof (default 1 MiB;
                          raise to match a gateway with a larger PASSPORT_MAX_REQUEST_BODY)`)
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
	tokenFile := fs.String("token-file", "", "file holding the bootstrap token (\"-\" reads stdin)")
	tokenEnv := fs.String("token-env", "PASSPORT_BOOTSTRAP_TOKEN", "env var holding the bootstrap token")
	// Defined only so removing it says why. A flag that vanishes into "flag provided but not
	// defined" reads as a version skew, and the natural fix is to find an older binary.
	legacy := fs.String("token", "", "removed: pass the bootstrap token by file or environment")
	keyFile := fs.String("key", "agent.key", "instance private key file (generated if missing)")
	out := fs.String("out", "cred.json", "file to write the issued workload credential to")
	_ = fs.Parse(args)

	if *legacy != "" {
		fmt.Fprintln(os.Stderr, `enroll: --token has been removed. A command line is world-readable
(ps, /proc/<pid>/cmdline) and lands in your shell history, so a bootstrap token passed that
way leaks to every other process on the host and outlives the command.

Use one of:
  passport enroll --authority URL --token-file bootstrap.token
  cat bootstrap.token | passport enroll --authority URL --token-file -
  PASSPORT_BOOTSTRAP_TOKEN=... passport enroll --authority URL`)
		os.Exit(2)
	}
	if *authority == "" {
		fmt.Fprintln(os.Stderr, "enroll: --authority is required")
		os.Exit(2)
	}
	token, err := readSecret(*tokenFile, *tokenEnv)
	if err != nil {
		log.Fatalf("enroll: bootstrap token: %v", err)
	}

	_, pub, err := loadOrGenKey(*keyFile)
	if err != nil {
		log.Fatalf("enroll: %v", err)
	}
	// The bootstrap token stays here: what goes on the wire is a MAC over the authority's
	// nonce and this public key, so it enrolls this key once and nothing else.
	cred, err := workload.Enroll(context.Background(), nil, *authority, pub,
		func(nonce []byte, pub ed25519.PublicKey) ([]byte, error) {
			return workload.BootstrapEvidence(token, nonce, pub), nil
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
	principalKeyFile := fs.String("principal-key", "", "the principal's did:key private key file (required by gateways in VC mode)")
	delegationFile := fs.String("delegation", "", "delegation chain JSON file (required by gateways with delegation enabled)")
	maxBody := fs.Int64("max-body", 0, "bytes of request body buffered to bind the proof (0 = 1 MiB; must be >= the gateway's PASSPORT_MAX_REQUEST_BODY)")
	_ = fs.Parse(args)

	if *gatewayURL == "" || *keyFile == "" || *credFile == "" {
		fmt.Fprintln(os.Stderr, "proxy: --gateway, --key and --credential are required")
		os.Exit(2)
	}
	if *tokenFile == "-" {
		fmt.Fprintln(os.Stderr, "proxy: --token-file - is not supported; the sidecar re-reads the token on every request (so rotating the file works) and stdin cannot be read twice")
		os.Exit(2)
	}

	key, err := loadPrivateKey(*keyFile)
	if err != nil {
		log.Fatalf("proxy: %v", err)
	}
	credHeader, err := loadCredHeader(*credFile)
	if err != nil {
		log.Fatalf("proxy: %v", err)
	}
	var principalKey ed25519.PrivateKey
	if *principalKeyFile != "" {
		if principalKey, err = loadPrivateKey(*principalKeyFile); err != nil {
			log.Fatalf("proxy: principal key: %v", err)
		}
	}
	var chainHeader string
	if *delegationFile != "" {
		if chainHeader, err = loadChainHeader(*delegationFile); err != nil {
			log.Fatalf("proxy: %v", err)
		}
	}

	h, err := newSidecar(sidecarConfig{
		gatewayURL:   *gatewayURL,
		instanceKey:  key,
		principalKey: principalKey,
		credHeader:   credHeader,
		chainHeader:  chainHeader,
		token:        tokenSource(*tokenFile, *tokenEnv),
		maxBody:      *maxBody,
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
	// principalKey is the principal's did:key private key, nil outside VC mode. The principal
	// credential is not a bearer token: a gateway in VC mode also wants a proof of possession
	// of this key, bound to each request (vc.HolderProof).
	principalKey ed25519.PrivateKey
	credHeader   string
	chainHeader  string
	token        func() (string, error)
	// maxBody caps the request body buffered to hash into the proof. It must be at least the
	// gateway's own PASSPORT_MAX_REQUEST_BODY, or a body the gateway would have accepted is
	// refused here first. Zero selects mcprpc.DefaultMaxBody, which is the gateway's default.
	maxBody int64
}

// bodyKey carries the buffered request body from the outer handler to the Director. The
// Director only receives the request, and the body is a one-shot reader it must not consume —
// the reverse proxy is about to forward those exact bytes upstream — so the bytes travel on
// the context, which ReverseProxy preserves when it clones the request.
type bodyKey struct{}

// newSidecar returns the reverse-proxy handler that injects passport credentials onto each
// request before forwarding to the gateway.
//
// The proof is computed PER REQUEST and cannot be otherwise: it commits to this request's
// method, target and body (workload.Proof). The previous sidecar built one proof at startup
// and reused it for the process's lifetime, which is what made a captured header bundle worth
// stealing — it was valid on every subsequent request too.
func newSidecar(cfg sidecarConfig) (http.Handler, error) {
	target, err := url.Parse(cfg.gatewayURL)
	if err != nil {
		return nil, fmt.Errorf("bad gateway URL: %w", err)
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	base := rp.Director
	rp.Director = func(r *http.Request) {
		base(r) // rewrites scheme/host/path to the gateway's, so the target is now final
		tok, err := cfg.token()
		if err != nil {
			// Leave credentials off; the gateway will deny (fail closed).
			return
		}
		body, _ := r.Context().Value(bodyKey{}).([]byte)
		proof, err := workload.Proof(cfg.instanceKey, r.Method, workload.ProofTarget(r.URL), tok, body)
		if err != nil {
			return // fail closed the same way: no proof, no admission
		}
		// The principal's own proof, when the deployment has a principal key: same binding,
		// different key and context. Built per request for the same reason the instance proof
		// is — it commits to this method, target and body.
		var holder string
		if cfg.principalKey != nil {
			if holder, err = vc.HolderProof(cfg.principalKey, r.Method, vc.ProofTarget(r.URL), tok, body); err != nil {
				return
			}
		}
		r.Header.Set("Authorization", "Bearer "+tok)
		r.Header.Set(workload.HeaderCredential, cfg.credHeader)
		r.Header.Set(workload.HeaderProof, proof)
		if holder != "" {
			r.Header.Set(vc.HeaderPrincipalProof, holder)
		}
		if cfg.chainHeader != "" {
			r.Header.Set(delegation.HeaderDelegation, cfg.chainHeader)
		}
	}

	// Buffering happens here rather than in the Director because that is the only place with
	// a ResponseWriter to cap the read against, and because the body has to be put back for
	// the proxy to forward byte-for-byte. It is the same mcprpc.BufferBody the gateway uses,
	// so both ends hash exactly the same bytes.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mcprpc.HasBody(r) {
			body, err := mcprpc.BufferBody(w, r, cfg.maxBody)
			if err != nil {
				status := http.StatusBadRequest
				if errors.Is(err, mcprpc.ErrBodyTooLarge) {
					status = http.StatusRequestEntityTooLarge
				}
				http.Error(w, http.StatusText(status), status)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), bodyKey{}, body))
		}
		rp.ServeHTTP(w, r)
	}), nil
}

// loadPrivateKey reads a base64url Ed25519 private key from a file. Both keys the sidecar
// holds — the instance key and the principal key — are stored in that one form.
func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("bad key encoding: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("key has wrong length")
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

// readSecret reads a token from a file — "-" being stdin — or, when no file is given, from an
// environment variable. Neither path is the command line, and that is the point: argv is
// readable by every process on the host (`ps`, /proc/<pid>/cmdline on Linux, which is
// world-readable) and the shell writes it to history, so a secret passed as an argument
// outlives the command and leaks sideways to any user on the box.
//
// A file is the better of the two: /proc/<pid>/environ is mode 0400 and readable only by the
// process owner and root, but the environment is inherited by every child the agent spawns,
// survives into core dumps and crash reports, and is what container platforms print back in a
// task description. A file can be mode 0600, mounted as a secret, replaced to rotate, and read
// once. The env var stays supported because it is what a container platform hands you and it
// is still strictly better than argv.
func readSecret(file, env string) (string, error) {
	switch {
	case file == "-":
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
		if err != nil {
			return "", fmt.Errorf("reading stdin: %w", err)
		}
		return trimmedOrError(string(b), "stdin was empty")
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		return trimmedOrError(string(b), fmt.Sprintf("%s is empty", file))
	default:
		return trimmedOrError(os.Getenv(env), fmt.Sprintf("no token in $%s (or pass --token-file)", env))
	}
}

func trimmedOrError(s, msg string) (string, error) {
	if t := strings.TrimSpace(s); t != "" {
		return t, nil
	}
	return "", errors.New(msg)
}

// tokenSource resolves the principal token per request rather than once at startup, so a
// rotated token file is picked up without restarting the sidecar. That is also why runProxy
// refuses "-" here: stdin cannot be read twice.
func tokenSource(file, env string) func() (string, error) {
	return func() (string, error) { return readSecret(file, env) }
}
