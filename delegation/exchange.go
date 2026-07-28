package delegation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/getsanad/sanad/internal/sigctx"
)

// Token is a centrally-issued delegation token (PRD FR-12a). Unlike the offline Capability,
// every Token is signed by the same ExchangeAuthority key, which lets the authority track
// the parent/child relationships and revoke any token mid-chain — tighter control at the
// cost of one round-trip per hop.
type Token struct {
	ID        string
	ParentID  string
	Principal string // root principal
	Subject   string // the delegate this token authorizes
	Grant     Grant
	IssuedAt  time.Time
	NotAfter  time.Time
	KeyID     string
	Signature []byte
}

// ExchangeAuthority issues and down-scopes delegation tokens via an online exchange
// (OAuth-2.0-token-exchange style). It is the centralized delegation mode (FR-12a).
type ExchangeAuthority struct {
	priv ed25519.PrivateKey
	kid  string
	ttl  time.Duration
	now  func() time.Time

	mu      sync.Mutex
	parent  map[string]string   // tokenID -> parentID (for ancestry-based revocation)
	revoked map[string]struct{} // revoked token ids (cascades to descendants)
}

// NewExchange returns an authority signing with priv (TTL defaults to 1h).
func NewExchange(priv ed25519.PrivateKey, kid string, ttl time.Duration) (*ExchangeAuthority, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("delegation: invalid exchange key")
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &ExchangeAuthority{
		priv: priv, kid: kid, ttl: ttl, now: time.Now,
		parent: map[string]string{}, revoked: map[string]struct{}{},
	}, nil
}

// PublicKey returns the key used to verify issued tokens.
func (a *ExchangeAuthority) PublicKey() ed25519.PublicKey { return a.priv.Public().(ed25519.PublicKey) }

// IssueRoot mints the first delegation token: principal -> subject under grant g.
func (a *ExchangeAuthority) IssueRoot(principal, subject string, g Grant) (Token, error) {
	return a.issue("", principal, subject, g)
}

// Exchange verifies the parent token and the requested narrowing, then issues a new
// narrower token for newSubject. The parent must be valid and not (ancestrally) revoked.
func (a *ExchangeAuthority) Exchange(parent Token, newSubject string, narrower Grant) (Token, error) {
	if err := a.Verify(parent, a.now()); err != nil {
		return Token{}, fmt.Errorf("delegation: parent token invalid: %w", err)
	}
	if err := attenuates(parent.Grant, narrower); err != nil {
		return Token{}, fmt.Errorf("delegation: exchange widens scope: %w", err)
	}
	return a.issue(parent.ID, parent.Principal, newSubject, narrower)
}

func (a *ExchangeAuthority) issue(parentID, principal, subject string, g Grant) (Token, error) {
	id, err := randID()
	if err != nil {
		return Token{}, err
	}
	now := a.now().UTC()
	t := Token{
		ID: id, ParentID: parentID, Principal: principal, Subject: subject,
		Grant: g, IssuedAt: now, NotAfter: now.Add(a.ttl), KeyID: a.kid,
	}
	t.Signature = sigctx.Sign(sigctx.ExchangeToken, a.priv, tokenMsg(t))

	a.mu.Lock()
	a.parent[id] = parentID
	a.mu.Unlock()
	return t, nil
}

// Verify checks the token's signature and validity window, and that neither it nor any
// ancestor has been revoked (centralized mid-chain revocation).
func (a *ExchangeAuthority) Verify(t Token, now time.Time) error {
	if !sigctx.Verify(sigctx.ExchangeToken, a.PublicKey(), tokenMsg(t), t.Signature) {
		return errors.New("delegation: invalid token signature")
	}
	if !t.NotAfter.IsZero() && !now.Before(t.NotAfter) {
		return errors.New("delegation: token expired")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	seen := map[string]struct{}{}
	for id := t.ID; id != ""; {
		if _, dup := seen[id]; dup {
			break // defensive: never loop on a corrupt parent map
		}
		seen[id] = struct{}{}
		if _, rev := a.revoked[id]; rev {
			return fmt.Errorf("delegation: token %q is revoked", id)
		}
		id = a.parent[id]
	}
	return nil
}

// Revoke revokes a token id; this cascades to every token exchanged from it (its subtree),
// because Verify walks the ancestry.
func (a *ExchangeAuthority) Revoke(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.revoked[id] = struct{}{}
}

func tokenMsg(t Token) []byte {
	b, _ := json.Marshal(struct {
		ID        string          `json:"id"`
		ParentID  string          `json:"parent"`
		Principal string          `json:"principal"`
		Subject   string          `json:"subject"`
		KeyID     string          `json:"kid"`
		Grant     json.RawMessage `json:"grant"`
		IssuedAt  int64           `json:"iat"`
		NotAfter  int64           `json:"exp"`
	}{t.ID, t.ParentID, t.Principal, t.Subject, t.KeyID, grantCanonical(t.Grant), t.IssuedAt.Unix(), t.NotAfter.Unix()})
	return b
}

func randID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
