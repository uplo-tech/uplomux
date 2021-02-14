package uplomux

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/uplo-tech/log"
	"github.com/uplo-tech/uplomux/helpers"
	"github.com/uplo-tech/uplomux/mux"
)

// TestInitPersist checks that persistence can be written/loaded from disk and
// that it ends up in the right place.
func TestInitPersist(t *testing.T) {
	mt, err := newMuxTester(testDir(t.Name()))
	if err != nil {
		t.Fatal(err)
	}
	// The mux should have valid keys.
	zeroPubKey := mux.ED25519PublicKey{}
	zeroPrivKey := mux.ED25519SecretKey{}
	if mt.staticPubKey == zeroPubKey {
		t.Fatal("staticPubKey wasn't set")
	}
	if mt.staticPrivKey == zeroPrivKey {
		t.Fatal("staticPrivKey wasn't set")
	}
	// Load the UploMux from disk again and check that the keys match.
	mt2, err := New("127.0.0.1:0", "127.0.0.1:0", log.DiscardLogger, mt.staticPersistDir)
	if err != nil {
		t.Fatal(err)
	}
	if mt.staticPubKey != mt2.staticPubKey {
		t.Fatal("public keys don't match")
	}
	if mt.staticPrivKey != mt2.staticPrivKey {
		t.Fatal("private keys don't match")
	}
	// Check the location of the persistence file.
	path := filepath.Join(mt.staticPersistDir, settingsName)
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

// TestCompatV1421 tests that the persistence is correctly overwritten when
// calling CompatV1421NewWithKeyPair.
func TestCompatV1421Persist(t *testing.T) {
	testDir := testDir(t.Name())
	privKey, pubKey := mux.GenerateED25519KeyPair()
	mt, err := CompatV1421NewWithKeyPair("127.0.0.1:0", "127.0.0.1:0", log.DiscardLogger, filepath.Join(testDir, helpers.RandomSuffix()), privKey, pubKey)
	if err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	// The mux should have valid keys.
	if mt.staticPubKey != pubKey {
		t.Fatal("staticPubKey wasn't set")
	}
	if mt.staticPrivKey != privKey {
		t.Fatal("staticPrivKey wasn't set")
	}
	// Load the UploMux from disk again and check that the keys match.
	mt2, err := New("127.0.0.1:0", "127.0.0.1:0", log.DiscardLogger, mt.staticPersistDir)
	if err != nil {
		t.Fatal(err)
	}
	if mt.staticPubKey != mt2.staticPubKey {
		t.Fatal("public keys don't match")
	}
	if mt.staticPrivKey != mt2.staticPrivKey {
		t.Fatal("private keys don't match")
	}
	// Check the location of the persistence file.
	path := filepath.Join(mt.staticPersistDir, settingsName)
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	// Load the UploMux from disk again and force new keys to be used.
	privKey, pubKey = mux.GenerateED25519KeyPair()
	mt3, err := CompatV1421NewWithKeyPair("127.0.0.1:0", "127.0.0.1:0", log.DiscardLogger, mt.staticPersistDir, privKey, pubKey)
	if err != nil {
		t.Fatal(err)
	}
	if mt3.staticPubKey != pubKey {
		t.Fatal("staticPubKey wasn't set")
	}
	if mt3.staticPrivKey != privKey {
		t.Fatal("staticPrivKey wasn't set")
	}
}
