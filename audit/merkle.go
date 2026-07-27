package audit

import (
	"bytes"
	"crypto/sha256"
	"errors"
)

// RFC 6962-style Merkle tree over the audit log. Inclusion proofs show an entry is in the
// log; consistency proofs show a newer log is an append-only extension of an older one —
// which detects both rewriting and tail-truncation (the limitation of a plain hash chain).
// Leaves are domain-separated (0x00 prefix) from internal nodes (0x01) per RFC 6962.

func hashLeaf(d []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(d)
	return h.Sum(nil)
}

func hashNode(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

// lp2 returns the largest power of two strictly less than n (n >= 2).
func lp2(n int) int {
	k := 1
	for k < n {
		k <<= 1
	}
	return k >> 1
}

// Root is the Merkle Tree Hash of the leaf data list.
func Root(leaves [][]byte) []byte {
	n := len(leaves)
	if n == 0 {
		return sha256.New().Sum(nil)
	}
	if n == 1 {
		return hashLeaf(leaves[0])
	}
	k := lp2(n)
	return hashNode(Root(leaves[:k]), Root(leaves[k:]))
}

// InclusionProof returns the audit path for the leaf at index.
func InclusionProof(leaves [][]byte, index int) ([][]byte, error) {
	if index < 0 || index >= len(leaves) {
		return nil, errors.New("audit: inclusion index out of range")
	}
	return inclusionPath(index, leaves), nil
}

func inclusionPath(m int, d [][]byte) [][]byte {
	n := len(d)
	if n == 1 {
		return nil
	}
	k := lp2(n)
	if m < k {
		return append(inclusionPath(m, d[:k]), Root(d[k:]))
	}
	return append(inclusionPath(m-k, d[k:]), Root(d[:k]))
}

// VerifyInclusion checks that leaf at index (in a tree of size) yields root, given proof.
func VerifyInclusion(leaf []byte, index, size int, proof [][]byte, root []byte) bool {
	got, ok := rootFromInclusion(hashLeaf(leaf), index, size, proof)
	return ok && bytes.Equal(got, root)
}

func rootFromInclusion(leafHash []byte, index, size int, proof [][]byte) ([]byte, bool) {
	if size <= 0 || index < 0 || index >= size {
		return nil, false
	}
	if size == 1 {
		if index == 0 && len(proof) == 0 {
			return leafHash, true
		}
		return nil, false
	}
	if len(proof) == 0 {
		return nil, false
	}
	k := lp2(size)
	last := proof[len(proof)-1]
	rest := proof[:len(proof)-1]
	if index < k {
		left, ok := rootFromInclusion(leafHash, index, k, rest)
		if !ok {
			return nil, false
		}
		return hashNode(left, last), true
	}
	right, ok := rootFromInclusion(leafHash, index-k, size-k, rest)
	if !ok {
		return nil, false
	}
	return hashNode(last, right), true
}

// ConsistencyProof proves the first oldSize leaves are a prefix of the current list.
func ConsistencyProof(leaves [][]byte, oldSize int) ([][]byte, error) {
	n := len(leaves)
	if oldSize < 0 || oldSize > n {
		return nil, errors.New("audit: consistency old size out of range")
	}
	if oldSize == 0 || oldSize == n {
		return nil, nil
	}
	return subproof(oldSize, leaves, true), nil
}

func subproof(m int, d [][]byte, b bool) [][]byte {
	n := len(d)
	if m == n {
		if b {
			return nil
		}
		return [][]byte{Root(d)}
	}
	k := lp2(n)
	if m <= k {
		return append(subproof(m, d[:k], b), Root(d[k:]))
	}
	return append(subproof(m-k, d[k:], false), Root(d[:k]))
}

// VerifyConsistency checks proof shows the tree of oldSize (oldRoot) is a prefix of the
// tree of newSize (newRoot). This is the RFC 6962 §2.1.2 verification algorithm.
func VerifyConsistency(oldSize, newSize int, proof [][]byte, oldRoot, newRoot []byte) bool {
	if oldSize < 0 || newSize < 0 || oldSize > newSize {
		return false
	}
	if oldSize == newSize {
		return len(proof) == 0 && bytes.Equal(oldRoot, newRoot)
	}
	if oldSize == 0 {
		return len(proof) == 0
	}

	node := oldSize - 1
	last := newSize - 1
	for node&1 == 1 {
		node >>= 1
		last >>= 1
	}

	p := 0
	var fr, sr []byte
	if node > 0 {
		if p >= len(proof) {
			return false
		}
		fr, sr = proof[p], proof[p]
		p++
	} else {
		fr, sr = oldRoot, oldRoot
	}

	for node > 0 {
		if node&1 == 1 {
			if p >= len(proof) {
				return false
			}
			fr = hashNode(proof[p], fr)
			sr = hashNode(proof[p], sr)
			p++
		} else if node < last {
			if p >= len(proof) {
				return false
			}
			sr = hashNode(sr, proof[p])
			p++
		}
		node >>= 1
		last >>= 1
	}

	for last > 0 {
		if p >= len(proof) {
			return false
		}
		sr = hashNode(sr, proof[p])
		p++
		last >>= 1
	}

	return bytes.Equal(fr, oldRoot) && bytes.Equal(sr, newRoot) && p == len(proof)
}
