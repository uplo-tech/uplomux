package mux

import (
	"reflect"
	"testing"

	"github.com/uplo-tech/errors"
	"github.com/uplo-tech/fastrand"
	"golang.org/x/crypto/chacha20poly1305"
)

// TestRequiredPackets tests the requiredPackets function.
func TestRequiredPackets(t *testing.T) {
	t.Parallel()
	// Initialize the cipher.
	key := fastrand.Bytes(X25519KeyLen)
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		t.Fatal(err)
	}
	// Declare some helper vars.
	packetSize := uint32(1440)
	overhead := marshaledFrameHeaderSize + uint32(2*(aead.NonceSize()+aead.Overhead()))

	// Prepare tests.
	tests := []struct {
		payloadLen      uint32
		requiredPackets uint32
		leftoverBytes   uint32
	}{
		// empty payload
		{
			payloadLen:      0,
			requiredPackets: 1,
			leftoverBytes:   1374,
		},
		// full packet
		{
			payloadLen:      packetSize - overhead,
			requiredPackets: 1,
			leftoverBytes:   0,
		},
		// full packet + 1
		{
			payloadLen:      packetSize - overhead + 1,
			requiredPackets: 2,
			leftoverBytes:   1439,
		},
		// 2 * full payload
		{
			payloadLen:      2*packetSize - overhead,
			requiredPackets: 2,
			leftoverBytes:   0,
		},
		// 2 * full payload + 1
		{
			payloadLen:      2*packetSize - overhead + 1,
			requiredPackets: 3,
			leftoverBytes:   1439,
		},
	}

	// Run tests.
	for _, test := range tests {
		rp, lb := requiredPackets(test.payloadLen, packetSize, aead)
		if rp != test.requiredPackets {
			t.Errorf("%v != %v", rp, test.requiredPackets)
		}
		if lb != test.leftoverBytes {
			t.Errorf("%v != %v", lb, test.leftoverBytes)
		}
	}
}

// TestMergeConnSettings tests if mergeConnSettings works as expected including
// all edge cases.
func TestMergeConnSettings(t *testing.T) {
	t.Parallel()
	// connection settings with very low values
	lowerSettings := connectionSettings{
		RequestedPacketSize: minPacketSize,
		MaxFrameSizePackets: lowerMaxFrameSizePackets,
		MaxTimeout:          LowerMaxTimeout,
	}
	// connection settings with higher values
	upperSettings := connectionSettings{
		RequestedPacketSize: minPacketSize + 1,
		MaxFrameSizePackets: upperMaxFrameSizePackets,
		MaxTimeout:          LowerMaxTimeout + 1,
	}
	// Merge the settings.
	merged1, err1 := mergeConnSettings(lowerSettings, upperSettings)
	merged2, err2 := mergeConnSettings(upperSettings, lowerSettings)
	if err := errors.Compose(err1, err2); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(merged1, merged2) {
		t.Log(merged1)
		t.Log(merged2)
		t.Fatal("merged1 and merged2 are not equal")
	}
	// The merged settings should equal the lowerSettings.
	if !reflect.DeepEqual(merged1, lowerSettings) {
		t.Log(merged1)
		t.Log(lowerSettings)
		t.Fatal("merged1 and lowerSettings are not equal")
	}
	// Test packetSize < minPacketSize
	errSettings := lowerSettings
	errSettings.RequestedPacketSize--
	_, err := mergeConnSettings(errSettings, lowerSettings)
	if !errors.Contains(err, errSmallPacketSize) {
		t.Fatal(err)
	}
	// Test frameSize < lowerFrameSize
	errSettings = lowerSettings
	errSettings.MaxFrameSizePackets--
	_, err = mergeConnSettings(errSettings, lowerSettings)
	if !errors.Contains(err, errSmallFrameSize) {
		t.Fatal(err)
	}
	// Test frameSize > upperFrameSize
	errSettings = upperSettings
	errSettings.MaxFrameSizePackets++
	_, err = mergeConnSettings(errSettings, errSettings)
	if !errors.Contains(err, errBigFrameSize) {
		t.Fatal(err)
	}
	// Test maxTimeout < lowerMaxTimeout
	errSettings = lowerSettings
	errSettings.MaxTimeout--
	_, err = mergeConnSettings(errSettings, lowerSettings)
	if !errors.Contains(err, errSmallMaxTimeout) {
		t.Fatal(err)
	}
}

// TODO ro-tex Add a unit test that reads a packed frame
