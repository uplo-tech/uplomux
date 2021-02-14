package helpers

import (
	"encoding/base32"
	"os"
	"path/filepath"
	"time"

	"github.com/uplo-tech/fastrand"
)

var (
	// UploMuxTestingDir is the directory that contains all of the files and
	// folders created during testing.
	UploMuxTestingDir = filepath.Join(os.TempDir(), "UploMuxTesting")
)

// RandomSuffix returns a 20 character base32 suffix for a filename. There are
// 100 bits of entropy, and a very low probability of colliding with existing
// files unintentionally.
func RandomSuffix() string {
	str := base32.StdEncoding.EncodeToString(fastrand.Bytes(20))
	return str[:20]
}

// Retry will call 'fn' 'tries' times, waiting 'durationBetweenAttempts'
// between each attempt, returning 'nil' the first time that 'fn' returns nil.
// If 'nil' is never returned, then the final error returned by 'fn' is
// returned.
func Retry(tries int, durationBetweenAttempts time.Duration, fn func() error) (err error) {
	for i := 1; i < tries; i++ {
		err = fn()
		if err == nil {
			return nil
		}
		time.Sleep(durationBetweenAttempts)
	}
	return fn()
}

// TestDir joins the provided directories and prefixes them with the Uplo testing
// directory.
func TestDir(dirs ...string) string {
	path := filepath.Join(UploMuxTestingDir, filepath.Join(dirs...))
	err := os.RemoveAll(path) // remove old test data
	if err != nil {
		panic(err)
	}
	return path
}
