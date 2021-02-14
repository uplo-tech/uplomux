package mux

import (
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"

	"golang.org/x/crypto/blake2b"

	"github.com/uplo-tech/fastrand"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

const (
	// X25519KeyLen is the length of a X25519 key and as a result the length of the
	// shared key.
	X25519KeyLen = 32
	// ED25519SecretKeyLen is the length of the private key used to create the
	// signature.
	ED25519SecretKeyLen = ed25519.PrivateKeySize
	// ED25519PublicKeyLen is the length of the public key used to verify
	// signatures.
	ED25519PublicKeyLen = ed25519.PublicKeySize
	// HashSize is the size of a blake2b 256bit hash.
	HashSize = blake2b.Size256
	// SignatureSize is the size of a ed25519 signature.
	SignatureSize = ed25519.SignatureSize
)

// encryptedHeaderSize is the encrypted size of a frame's header given a
// specific cipher.
func encryptedHeaderSize(aead cipher.AEAD) int {
	return marshaledFrameHeaderSize + aead.Overhead() + aead.NonceSize()
}

// maxFramePayloadSize is the maximum size a frame's payload can have to still
// be below encryptedFrameSize when encrypted and combined with an encrypted
// header.
func maxFramePayloadSize(encryptedFrameSize uint32, aead cipher.AEAD) int {
	return int(encryptedFrameSize) - encryptedHeaderSize(aead) - aead.Overhead() - aead.NonceSize()
}

type (
	// CipherSpecifier is a specifier used to identify the cipher being used for
	// encryption.
	CipherSpecifier [16]byte
	// Hash is the result of hashing data in the uplomux protocol.
	Hash [HashSize]byte
	// Signature is the type of a ed25519 signature.
	Signature [SignatureSize]byte
	// An X25519SecretKey is the secret half of an X25519 key pair.
	X25519SecretKey [X25519KeyLen]byte
	// An X25519PublicKey is the public half of an X25519 key pair.
	X25519PublicKey [X25519KeyLen]byte
	// An ED25519SecretKey is the private half of an ED25519 key pair.
	ED25519SecretKey [ED25519SecretKeyLen]byte
	// An ED25519PublicKey is the public half of an ED25519 key pair.
	ED25519PublicKey [ED25519PublicKeyLen]byte
)

var (
	// CipherSpecifierChaCha20Poly1305 is the specifier for the chacha20poly1305
	// aead cipher.
	CipherSpecifierChaCha20Poly1305 = CipherSpecifier{'C', 'h', 'a', 'c', 'h', 'a', '2', '0', 'P', '1', '3', '0', '5'}
)

type (
	// establishEncryptionRequest is the request sent by the client a.k.a. the
	// peer establishing the connection.
	establishEncryptionRequest struct {
		// PublicKey is the ephemeral public key of the client.
		PublicKey X25519PublicKey
		// Ciphers supported by the client.
		Ciphers []CipherSpecifier
	}
	// establishEncryptionResponse is the response sent by the server a.k.a the
	// peer being connected to.
	establishEncryptionResponse struct {
		// PublicKey is the server's ephemeral public key which is used to
		// derive the shared secret.
		PublicKey X25519PublicKey
		// Signature of (Server's ephemeral Public key | Client's Ephemeral
		// Public Key) signed with the server's non-ephemeral private key. This
		// is used to authenticate the server if the server's non-ephemeral
		// public key was known beforehand.
		Signature Signature
		// Cipher selected by the server. Must be one of the ciphers offered in
		// the establishEncryptionRequest.
		Cipher CipherSpecifier
	}
)

// createSignatureHash takes the public key of the encryptionRequest and the
// public key of the encryptionResponse and hashes them together.
func createSignatureHash(responsePubKey, requestPubKey X25519PublicKey) Hash {
	return blake2b.Sum256(append(responsePubKey[:], requestPubKey[:]...))
}

// deriveSharedSecret derives 32 bytes of entropy from a secret key and public
// key. Derivation is via ScalarMult of the private and public keys.
func deriveSharedSecret(xsk X25519SecretKey, xpk X25519PublicKey) (secret [X25519KeyLen]byte) {
	curve25519.ScalarMult(&secret, (*[X25519KeyLen]byte)(&xsk), (*[X25519KeyLen]byte)(&xpk))
	return
}

// generateX25519KeyPair generates an ephemeral key pair for use in ECDH.
func generateX25519KeyPair() (xsk X25519SecretKey, xpk X25519PublicKey) {
	fastrand.Read(xsk[:])
	curve25519.ScalarBaseMult((*[X25519KeyLen]byte)(&xpk), (*[X25519KeyLen]byte)(&xsk))
	return
}

// GenerateED25519KeyPair creates a public-secret keypair that can be used to
// sign and verify messages.
func GenerateED25519KeyPair() (sk ED25519SecretKey, pk ED25519PublicKey) {
	// no error possible when using fastrand.Reader
	epk, esk, _ := ed25519.GenerateKey(fastrand.Reader)
	copy(sk[:], esk)
	copy(pk[:], epk)
	return
}

// encryptFrameHeader encrypts a frame's header.
func encryptFrameHeader(header []byte, aead cipher.AEAD) ([]byte, error) {
	if len(header) != marshaledFrameHeaderSize {
		return nil, fmt.Errorf("unexpected header size %v != %v", len(header), marshaledFrameHeaderSize)
	}
	nonce := fastrand.Bytes(aead.NonceSize())
	return aead.Seal(nonce, nonce, header, nil), nil // reuse nonce memory by passing it in as dst too
}

// encryptFramePayload encrypts a frame's payload. The resulting ciphertext
// will be padded to encryptedFrameSize bytes.
func encryptFramePayload(p []byte, encryptedFrameSize uint32, aead cipher.AEAD) ([]byte, error) {
	// copy payload to prevent data race.
	payload := append([]byte{}, p...)
	// check input
	maxPayloadSize := maxFramePayloadSize(encryptedFrameSize, aead)
	if len(payload) > maxPayloadSize {
		return nil, fmt.Errorf("payload is too big (%v) to fit in a frame of size %v with capacity %v", len(payload), encryptedFrameSize, maxPayloadSize)
	}
	if len(payload) < maxPayloadSize {
		payload = append(payload, make([]byte, maxPayloadSize-len(payload))...)
	}
	// encrypt payload
	nonce := fastrand.Bytes(aead.NonceSize())
	c := aead.Seal(nonce, nonce, payload, nil) // reuse nonce memory by passing it in as dst too
	return c, nil
}

// decryptFrameHeader decrypts a frame's header.
func decryptFrameHeader(header []byte, aead cipher.AEAD) ([]byte, error) {
	if len(header) != encryptedHeaderSize(aead) {
		return nil, fmt.Errorf("unexpected encrypted header size %v != %v", len(header), encryptedHeaderSize(aead))
	}
	nonce, ciphertext := header[:aead.NonceSize()], header[aead.NonceSize():]
	return aead.Open(nil, nonce, ciphertext, nil)
}

// decryptFramePayload decrypts a frame's payload.
func decryptFramePayload(payload []byte, aead cipher.AEAD) ([]byte, error) {
	nonce, ciphertext := payload[:aead.NonceSize()], payload[aead.NonceSize():]
	return aead.Open(nil, nonce, ciphertext, nil)
}

// initCipher creates an AEAD from a cipher specifier and key. If the specifier
// is unknown, an error is returned.
func initCipher(key []byte, cipher CipherSpecifier) (cipher.AEAD, error) {
	switch cipher {
	case CipherSpecifierChaCha20Poly1305:
		return chacha20poly1305.New(key)
	default:
	}
	return nil, fmt.Errorf("unknown cipher %v", cipher)
}

// signHash signs a message using a secret key.
func signHash(data Hash, sk ED25519SecretKey) (sig Signature) {
	copy(sig[:], ed25519.Sign(sk[:], data[:]))
	return
}

// verifyHash uses a public key and input data to verify a signature.
func verifyHash(data Hash, pk ED25519PublicKey, sig Signature) bool {
	return ed25519.Verify(pk[:], data[:], sig[:])
}
