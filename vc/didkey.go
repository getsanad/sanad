// Package vc implements W3C Verifiable-Credential-style principal credentials (PRD FR-2,
// §11) using non-blockchain DIDs. A trusted issuer signs a credential binding a principal
// DID to an assurance level; the gateway verifies it as an alternative to OIDC (P1-03).
//
// Because a did:key embeds the subject's public key, verifying a principal's VC also yields
// that principal's key — which we register so delegation chains rooted at the principal
// verify (closing the P2-02 gap). did:web (which needs network resolution) is a follow-up.
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
