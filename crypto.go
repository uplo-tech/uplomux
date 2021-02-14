package uplomux

import (
	"hash"

	"golang.org/x/crypto/blake2b"

	"github.com/uplo-tech/encoding"
)

const (
	// HashSize is the length of a Hash in bytes.
	HashSize = 32
)

type (
	// Hash is a BLAKE2b 256-bit digest.
	Hash [HashSize]byte
)

// NewHash returns a blake2b 256bit hasher.
func NewHash() hash.Hash {
	h, _ := blake2b.New256(nil) // cannot fail with nil argument
	return h
}

// HashAll takes a set of objects as input, encodes them all using the encoding
// package, and then hashes the result.
func HashAll(objs ...interface{}) (hash Hash) {
	h := NewHash()
	enc := encoding.NewEncoder(h)
	for _, obj := range objs {
		_ = enc.Encode(obj)
	}
	h.Sum(hash[:0])
	return
}
