package mux

import (
	"bytes"
	"testing"

	"github.com/uplo-tech/fastrand"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

// TestDeriveSharedSecret checks that deriveSharedSecret correctly computes the
// shared secret used to encrypt the communication between two peers.
func TestDeriveSharedSecret(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	t.Parallel()

	// Create 2 key pairs.
	privKey1, pubKey1 := generateX25519KeyPair()
	privKey2, pubKey2 := generateX25519KeyPair()
	// Derive the shared key twice.
	sharedKey1 := deriveSharedSecret(privKey1, pubKey2)
	sharedKey2 := deriveSharedSecret(privKey2, pubKey1)
	// The shared keys should match.
	if !bytes.Equal(sharedKey1[:], sharedKey2[:]) {
		t.Log("privKey1", privKey1)
		t.Log("pubKey1", pubKey1)
		t.Log("privKey2", privKey2)
		t.Log("pubKey2", pubKey2)
		t.Log("sharedKey1", sharedKey1)
		t.Log("sharedKey2:", sharedKey2)
		t.Fatal("shared keys don't match")
	}
}

// TestEncryptDecryptFrameHeader tests encryptFrameHeader and
// decryptFrameHeader.
func TestEncryptDecryptFrameHeader(t *testing.T) {
	t.Parallel()
	// Create a random key.
	key := fastrand.Bytes(X25519KeyLen)

	// Initialize the cipher.
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		t.Fatal(err)
	}
	// Create a frame that is maller than the encryptedFrameSize, one that is
	// the same size and one that is bigger to test for edge cases.
	smallHeader := fastrand.Bytes(marshaledFrameHeaderSize - 1)
	mediumHeader := fastrand.Bytes(marshaledFrameHeaderSize)
	largeHeader := fastrand.Bytes(marshaledFrameHeaderSize + 1)

	// Encrypt the frames. Should work for the small and medium frame but not the
	// large one.
	_, err = encryptFrameHeader(smallHeader, aead)
	if err == nil {
		t.Fatal("encrypting the smallHeader should have failed but didn't")
	}
	mediumFrameEncrypted, err := encryptFrameHeader(mediumHeader, aead)
	if err != nil {
		t.Fatal(err)
	}
	_, err = encryptFrameHeader(largeHeader, aead)
	if err == nil {
		t.Fatal("encrypting the largeHeader should have failed but didn't")
	}

	// Check the size of the encrypted frame.
	if len(mediumFrameEncrypted) != encryptedHeaderSize(aead) {
		t.Fatalf("expected frame to have size %v but was %v", encryptedHeaderSize(aead), len(mediumFrameEncrypted))
	}

	// Decrypt the frame again. The decrypted frames minus padding should match
	// the original data.
	mediumHeader2, err := decryptFrameHeader(mediumFrameEncrypted, aead)
	if err != nil {
		t.Fatal(err)
	}
	mediumHeader2 = mediumHeader2[:len(mediumHeader)]
	if !bytes.Equal(mediumHeader, mediumHeader2) {
		t.Fatal("frames don't match")
	}
}

// TestEncryptDecryptFramePayload tests encryptFramePayload and
// decryptFramePayload. It checks if the encryption inputs are checked
// correctly, if padding is applied correctly and whether the decryption
// produces the same plaintext as before.
func TestEncryptDecryptFramePayload(t *testing.T) {
	t.Parallel()
	// Create a random key.
	key := fastrand.Bytes(X25519KeyLen)

	// Initialize the cipher.
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		t.Fatal(err)
	}
	// Create a frame that is maller than the encryptedFrameSize, one that is
	// the same size and one that is bigger to test for edge cases.
	encryptedFrameSize := uint32(ipV4PacketSize)
	encryptedFramePayloadSize := int(encryptedFrameSize) - marshaledFrameHeaderSize - aead.Overhead() - aead.NonceSize()
	mfs := maxFramePayloadSize(encryptedFrameSize, aead)
	smallFrame := fastrand.Bytes(mfs - 1)
	mediumFrame := fastrand.Bytes(mfs)
	largeFrame := fastrand.Bytes(mfs + 1)

	// Encrypt the frames. Should work for the small and medium frame but not the
	// large one.
	smallFrameEncrypted, err := encryptFramePayload(smallFrame, encryptedFrameSize, aead)
	if err != nil {
		t.Fatal(err)
	}
	mediumFrameEncrypted, err := encryptFramePayload(mediumFrame, encryptedFrameSize, aead)
	if err != nil {
		t.Fatal(err)
	}
	_, err = encryptFramePayload(largeFrame, encryptedFrameSize, aead)
	if err == nil {
		t.Fatal("encrypting the largeFrame should have failed but didn't")
	}

	// Check the size of the encrypted frames.
	if len(smallFrameEncrypted) != encryptedFramePayloadSize {
		t.Fatalf("expected frame to have size %v but was %v", encryptedFramePayloadSize, len(smallFrameEncrypted))
	}
	if len(mediumFrameEncrypted) != encryptedFramePayloadSize {
		t.Fatalf("expected frame to have size %v but was %v", encryptedFramePayloadSize, len(mediumFrameEncrypted))
	}

	// Decrypt the frames again. The decrypted frames minus padding should match
	// the original data.
	smallFrame2, err := decryptFramePayload(smallFrameEncrypted, aead)
	if err != nil {
		t.Fatal(err)
	}
	mediumFrame2, err := decryptFramePayload(mediumFrameEncrypted, aead)
	if err != nil {
		t.Fatal(err)
	}
	smallFrame2 = smallFrame2[:len(smallFrame)]
	mediumFrame2 = mediumFrame2[:len(mediumFrame)]
	if !bytes.Equal(smallFrame, smallFrame2) {
		t.Fatal("frames don't match")
	}
	if !bytes.Equal(mediumFrame, mediumFrame2) {
		t.Fatal("frames don't match")
	}
}

// TestSignVerifyHash tests if creating signatures for hashes and verifying them
// works as expected.
func TestSignVerifyHash(t *testing.T) {
	t.Parallel()
	// Create some random data.
	data := fastrand.Bytes(100)
	// Generate a keypair.
	sk, pk := GenerateED25519KeyPair()
	// Hash the data.
	hash := blake2b.Sum256(data)
	// Sign the data.
	sig := signHash(hash, sk)
	// Verify signature
	if !verifyHash(hash, pk, sig) {
		t.Fatal("signature wasn't verified")
	}
}
