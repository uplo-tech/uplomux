package mux

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/uplo-tech/fastrand"
	"golang.org/x/crypto/chacha20poly1305"
)

// TestEstablishEncryptionRequestResponseSize sanity checks whether the size of
// an encryptionRequestFrame and encryptionResponseFrame match their
// corresponding constants.
func TestEstablishEncryptionRequestResponseSize(t *testing.T) {
	_, _, reqFrame := newEstablishEncryptionRequestFrame()
	d, err := reqFrame.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if len(d) != marshaledEstablishEncryptionRequestFrameSize {
		t.Fatalf("expected len(d) to be %v but was %v", marshaledEstablishEncryptionRequestFrameSize, len(d))
	}
	_, _, respFrame := newEstablishEncryptionResponseFrame(X25519PublicKey{}, ED25519SecretKey{})
	d, err = respFrame.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if len(d) != marshaledEstablishEncryptionResponseFrameSize {
		t.Fatalf("expected len(d) to be %v but was %v", marshaledEstablishEncryptionResponseFrameSize, len(d))
	}
}

// TestMarshalUnmarshalFrame checks if a frame can be marshaled, padded and then
// unmarshalled correctly.
func TestMarshalUnmarshalFrame(t *testing.T) {
	// Create frame with random payload.
	length := fastrand.Intn(3) // [0;2]
	f := frame{
		frameHeader: frameHeader{
			id:     uint32(fastrand.Intn(100)),
			length: uint32(length),
			flags:  uint16(fastrand.Intn(100)),
		},
		payload: fastrand.Bytes(length),
	}
	// Marshal it.
	b, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	// Add some random padding to the marshaled frame.
	b = append(b, fastrand.Bytes(fastrand.Intn(3))...)
	// Unmarshal it.
	var f2 frame
	if err := f2.Unmarshal(b); err != nil {
		t.Fatal(err)
	}
	// The result should match the original.
	if !reflect.DeepEqual(f, f2) {
		t.Fatal("unmarshalled frame doesn't match original")
	}
}

// TestWriteReadFrame tests the writeFrame and readFrame methods.
func TestWriteReadFrame(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	t.Parallel()

	// Define some variables
	minFrameSizePackets := minFrameSizePackets
	maxFrameSizePackets := upperMaxFrameSizePackets

	packetStats := make(map[uint32]int)
	// Try a bunch of random payloads.
	for i := 0; i < 1000; i++ {
		// Create a random cipher.
		key := fastrand.Bytes(X25519KeyLen)
		aead, err := chacha20poly1305.New(key[:])
		if err != nil {
			t.Fatal(err)
		}

		// Decide on a random number of valid packets to use at most.
		numPacketsAboveMin := uint32(fastrand.Uint64n(uint64(maxFrameSizePackets-minFrameSizePackets) + 1))
		numPackets := minFrameSizePackets + numPacketsAboveMin
		encryptedFrameSize := numPackets * ipV4PacketSize

		// Collect stats.
		packetStats[numPackets]++

		// Get the maximum payload size to fit within those packets.
		maxPayloadSize := maxFramePayloadSize(encryptedFrameSize, aead)

		var actualPayloadSize int
		switch fastrand.Intn(2) {
		case 0:
			// Use maxPayloadSize to get exactly numPackets full packets.
			actualPayloadSize = maxPayloadSize
		case 1:
			// Subtract 1 to get a packet that's not quite full.
			actualPayloadSize = maxPayloadSize - 1
		default:
			t.Fatal("shouldn't happen")
		}

		// Create frame with random payload.
		f := frame{
			frameHeader: frameHeader{
				id:     uint32(fastrand.Intn(100)),
				length: uint32(actualPayloadSize),
				flags:  uint16(fastrand.Intn(100)),
			},
			payload: fastrand.Bytes(actualPayloadSize),
		}
		// Prepare a buffer for the encrypted frame.
		buf := bytes.NewBuffer(make([]byte, 0, encryptedFrameSize))
		// Write the frame to the buffer.
		n, err := writeFrame(buf, aead, f, minFrameSizePackets, maxFrameSizePackets, ipV4PacketSize)
		if err != nil {
			t.Fatal(err)
		}
		if uint32(n) != encryptedFrameSize {
			t.Fatalf("n should be %v but was %v", encryptedFrameSize, n)
		}
		// Read the frame from the buffer.
		n, f2, _, err := readFrame(buf, aead, encryptedFrameSize, ipV4PacketSize)
		if err != nil {
			t.Fatal(err)
		}
		if uint32(n) != encryptedFrameSize {
			t.Fatalf("expected %v but got %v", encryptedFrameSize, n)
		}
		// Compare the frames.
		if !reflect.DeepEqual(f, f2) {
			t.Log(f)
			t.Log(f2)
			t.Fatal("read frame doesn't match written frame")
		}
	}
	t.Logf("# of executions per chosen packet count: %v", packetStats)
}
