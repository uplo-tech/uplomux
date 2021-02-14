package uplomux

import (
	"os"
	"path/filepath"

	"github.com/uplo-tech/errors"
	"github.com/uplo-tech/persist"
	"github.com/uplo-tech/uplomux/mux"
)

const (
	// persistDirPerms are the permissions used when creating the persist dir of
	// the UploMux.
	persistDirPerms = 0700
	// persistFilePerms are the permission used when creating the metadata
	// persist file.
	persistFilePerms = 0600
	// settingsName is the name of the file which stores the uplomux settings
	// a.k.a. the persistence struct.
	settingsName = "uplomux.json"
)

var (
	// persistMetadata is the metadata written to disk when persisting the
	// UploMux.
	persistMetadata = persist.Metadata{
		Header:  "UploMux",
		Version: "1.4.2.1",
	}
)

type (
	// persistence is the data persisted to disk by the UploMux.
	persistence struct {
		PubKey  mux.ED25519PublicKey `json:"pubkey"`
		PrivKey mux.ED25519SecretKey `json:"privkey"`
	}
)

// initPersist loads the persistence of the UploMux or creates a new one with
// fresh keys in case it doesn't exist yet.
func (sm *UploMux) initPersist() error {
	// Create the persist dir.
	if err := os.MkdirAll(sm.staticPersistDir, persistDirPerms); err != nil {
		return errors.AddContext(err, "failed to create UploMux persist dir")
	}
	// Get the filepath.
	path := filepath.Join(sm.staticPersistDir, settingsName)
	// Load the persistence object
	var data persistence
	err := persist.LoadJSON(persistMetadata, &data, path)
	if os.IsNotExist(err) {
		// If the data isn't persisted yet we create new keys and persist them.
		privKey, pubKey := mux.GenerateED25519KeyPair()
		data.PrivKey = privKey
		data.PubKey = pubKey
		if err = persist.SaveJSON(persistMetadata, data, path); err != nil {
			return errors.AddContext(err, "failed to initialize fresh persistence")
		}
		if err := os.Chmod(path, persistFilePerms); err != nil {
			return errors.AddContext(err, "failed to set the mode of the UploMux metadata persist file")
		}
	}
	if err != nil {
		return errors.AddContext(err, "failed to load persistence data from disk")
	}
	// Set the fields in the UploMux
	sm.staticPrivKey = data.PrivKey
	sm.staticPubKey = data.PubKey
	return nil
}

// persistData creates a persistence object from the UploMux.
func (sm *UploMux) persistData() persistence {
	return persistence{
		PubKey:  sm.staticPubKey,
		PrivKey: sm.staticPrivKey,
	}
}

// savePersist writes the persisted fields of the UploMux to disk.
func (sm *UploMux) savePersist() error {
	path := filepath.Join(sm.staticPersistDir, settingsName)
	return errors.AddContext(persist.SaveJSON(persistMetadata, sm.persistData(), path), "failed to save persistence data")
}
