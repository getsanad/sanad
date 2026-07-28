// Package vc implements W3C Verifiable-Credential-style principal credentials (PRD FR-2,
// §11) using non-blockchain DIDs. A trusted issuer signs a credential binding a principal
// DID to an assurance level; the gateway verifies it as an alternative to OIDC (P1-03).
//
// Because a did:key embeds the subject's public key, verifying a principal's VC also yields
// that principal's key — which we register so delegation chains rooted at the principal
// verify (closing the P2-02 gap). did:web (which needs network resolution) is a follow-up.
//
// # Presenting one requires the subject's key
//
// Verifying the issuer's signature says the credential is genuine. It says nothing about who
// is holding it. Without a second check the credential is a bearer token whose bearer is a
// human being's identity for its whole lifetime: copy the base64 out of one Authorization
// header — from a log, a proxy, the upstream server — and you are that principal. That is the
// exact property a key-based DID exists to avoid, since the subject's public key is sitting
// right there in the identifier, unused.
//
// So presenting a credential also requires proving possession of the subject's private key,
// over THIS request. HolderProof and Authenticator.AuthenticateRequest are that binding, and
// holder.go documents why it is a request binding rather than a server-issued challenge.
//
// # This is a VC-shaped profile, not a JSON-LD implementation
//
// The credential is a W3C VC in shape — @context, type, credentialSubject, proof, all
// enforced by Verify — but the proof is NOT one of the registered Data Integrity suites and
// does not claim to be. Those are defined over JSON-LD canonicalization (URDNA2015) of the
// credential graph; canonical signs a marshal of the Go struct, and the proof type says so
// (see proofType). Two consequences worth stating plainly:
//
//   - A spec-conformant VC verifier will not verify these credentials, and this package will
//     not verify credentials issued by one. Interoperating with the wider VC ecosystem means
//     adopting URDNA2015 and a registered suite; that is a follow-up, not a claim made here.
//   - Because the signing input is a struct marshal, a property the struct does not model is
//     a property no signature covers. decodeCredential therefore REFUSES unknown properties
//     rather than letting encoding/json drop them, which is what would otherwise let an
//     unsigned field ride along invisibly through verification.
package vc

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// base58btc alphabet (Bitcoin/IPFS), the multibase 'z' encoding used by did:key.
const b58alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// ed25519 multicodec prefix (0xed 0x01) per the did:key spec.
var ed25519Prefix = []byte{0xed, 0x01}

const didKeyPrefix = "did:key:z" // "did:key:" + multibase 'z' (base58btc)

// EncodeDIDKey returns the did:key identifier for an Ed25519 public key.
func EncodeDIDKey(pub ed25519.PublicKey) string {
	data := append(append([]byte{}, ed25519Prefix...), pub...)
	return didKeyPrefix + base58Encode(data)
}

// PublicKeyFromDID extracts the Ed25519 public key from a did:key identifier.
func PublicKeyFromDID(did string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(did, didKeyPrefix) {
		return nil, errors.New("vc: not a base58btc did:key")
	}
	data, err := base58Decode(did[len(didKeyPrefix):])
	if err != nil {
		return nil, fmt.Errorf("vc: bad did:key: %w", err)
	}
	if len(data) != len(ed25519Prefix)+ed25519.PublicKeySize || data[0] != 0xed || data[1] != 0x01 {
		return nil, errors.New("vc: did:key is not an Ed25519 key")
	}
	return ed25519.PublicKey(data[len(ed25519Prefix):]), nil
}

func base58Encode(input []byte) string {
	zeros := 0
	for zeros < len(input) && input[zeros] == 0 {
		zeros++
	}
	x := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	mod := new(big.Int)
	var out []byte
	for x.Sign() > 0 {
		x.DivMod(x, base, mod)
		out = append(out, b58alphabet[mod.Int64()])
	}
	for range zeros {
		out = append(out, b58alphabet[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func base58Decode(s string) ([]byte, error) {
	x := new(big.Int)
	base := big.NewInt(58)
	for _, r := range s {
		idx := strings.IndexRune(b58alphabet, r)
		if idx < 0 {
			return nil, fmt.Errorf("invalid base58 character %q", r)
		}
		x.Mul(x, base)
		x.Add(x, big.NewInt(int64(idx)))
	}
	decoded := x.Bytes()
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	return append(make([]byte, zeros), decoded...), nil
}
