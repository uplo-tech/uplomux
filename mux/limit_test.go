package mux

import (
	"io"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uplo-tech/errors"
	"github.com/uplo-tech/fastrand"
	"github.com/uplo-tech/uplomux/deps"
)

var (
	errDownloadLimitReached = errors.New("download limit reached")
	errUploadLimitReached   = errors.New("upload limit reached")
)

// testLimit is a simple BandwidthLimit implementation for testing.
type testLimit struct {
	downloadLimit uint64
	uploadLimit   uint64

	downloaded uint64
	uploaded   uint64

	mu sync.Mutex
}

// newTestLimit returns a new testLimit object.
func newTestLimit(down, up uint64) BandwidthLimit {
	return &testLimit{
		downloadLimit: down,
		uploadLimit:   up,
	}
}

// Downloaded implements the BandwidthLimit interface.
func (tl *testLimit) Downloaded() uint64 {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	return tl.downloaded
}

// Uploaded implements the BandwidthLimit interface.
func (tl *testLimit) Uploaded() uint64 {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	return tl.uploaded
}

// RecordDownload implements the BandwidthLimit interface.
func (tl *testLimit) RecordDownload(bytes uint64) error {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	if tl.downloaded+bytes > tl.downloadLimit {
		return errDownloadLimitReached
	}
	tl.downloaded += bytes
	return nil
}

// RecordUpload implements the BandwidthLimit interface.
func (tl *testLimit) RecordUpload(bytes uint64) error {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	if tl.uploaded+bytes > tl.uploadLimit {
		return errUploadLimitReached
	}
	tl.uploaded += bytes
	return nil
}

type (
	// dependencySlowWrite adds a sleep between each written frame. This
	// dependency is used by tests which need to test events that happen
	// mid-write. e.g. that receiving an error frame for a stream while writing
	// to the stream will return an error on the call to 'Write'.
	dependencySlowWrite struct {
		deps.ProductionDependencies
		delay time.Duration
	}
)

// newDependencySlowWrite creates a new dependencySlowWrite dependency from
// the specified delay.
func newDependencySlowWrite(delay time.Duration) deps.Dependencies {
	return &dependencySlowWrite{
		delay: delay,
	}
}

// Disrupt will return 'true' if the string 'slowWrite' is provided which causes
// delays between writing payload frames in the mux.
func (dsw *dependencySlowWrite) Disrupt(s string) bool {
	if s == "slowWrite" {
		time.Sleep(dsw.delay)
		return true
	}
	return false
}

// TestBandwidthLimit_RecordDownload tests setting a download limit.
func TestBandwidthLimit_RecordDownload(t *testing.T) {
	client, server := createTestingMuxs()
	defer client.Close()
	defer server.Close()
	// data should make up for 10 full frames.
	numFrames := uint64(10)
	frameSize := uint64(client.settings.MaxFrameSize())
	maxPayload := maxFramePayloadSize(client.settings.MaxFrameSize(), client.staticAead) - marshaledFrameHeaderSize
	data := fastrand.Bytes(maxPayload * int(numFrames))
	rawData := numFrames * frameSize

	start := make(chan struct{})
	// Server thread.
	serverWorker := func() {
		<-start
		// Wait for a stream.
		stream, err := server.AcceptStream()
		if err != nil {
			t.Error(err)
			return
		}
		// Set the download limit to be half the length of the expected data.
		// This way we receive some frames before the limit is reached and also
		// afterwards.
		l := newTestLimit(rawData/2, math.MaxUint64)
		err = stream.SetLimit(l)
		if err != nil {
			t.Error(err)
			return
		}
		// Read some data. This should fail.
		readData := make([]byte, len(data))
		_, err = io.ReadFull(stream, readData)
		if !errors.Contains(err, errDownloadLimitReached) {
			t.Error(err)
			return
		}
		// The limit should report rawData/2 downloaded bytes.
		if l.Downloaded() != rawData/2 {
			t.Errorf("expected %v bytes but got %v", rawData/2, l.Downloaded())
		}
		// Wait for another stream without closing the initial one. That way we
		// make sure that a triggered limit will correctly unblock the peer.
		stream, err = server.AcceptStream()
		if err != nil {
			t.Error(err)
			return
		}
		// Set the download limit to be exactly the length of the expected data.
		l = newTestLimit(rawData, math.MaxUint64)
		err = stream.SetLimit(l)
		if err != nil {
			t.Error(err)
			return
		}
		// Read some data. This should not fail.
		_, err = io.ReadFull(stream, readData)
		if err != nil {
			t.Error(err)
			return
		}
		// The limit should report rawData downloaded bytes.
		time.Sleep(time.Second)
		if l.Downloaded() != rawData {
			t.Errorf("expected %v bytes but got %v", rawData, l.Downloaded())
		}
		// Close the stream.
		if err := stream.Close(); err != nil {
			t.Error(err)
			return
		}
	}
	// Client thread.
	clientWorker := func() {
		<-start
		// Make sure the client writes slowly to the connection.
		client.staticDeps = newDependencySlowWrite(100 * time.Millisecond)
		// The server thread is expecting 2 iterations.
		for i := 0; i < 2; i++ {
			// Create a new stream.
			stream, err := client.NewStream()
			if err != nil {
				t.Error(err)
				return
			}
			// Write some data.
			_, err = stream.Write(data)
			// The write in the first iteration fails cause the host's limit
			// triggers.
			if i == 0 && (err == nil || !strings.Contains(err.Error(), errDownloadLimitReached.Error())) {
				t.Error("write should have failed but didn't")
				return
			}
			// The write in the second iteration passes.
			if i == 1 && err != nil {
				t.Error(err)
				return
			}
			// Check the stats of iteration 1.
			limit := stream.Limit()
			downloaded := limit.Downloaded()
			uploaded := limit.Uploaded()
			if i == 0 {
				// No data downloaded in this test.
				if downloaded != 0 {
					t.Errorf("%v: expected %v bytes downloaded but got %v", i, 0, downloaded)
				}
				// The host limit was set to half the data. So at least half
				// data has to be counted.
				if uploaded < rawData/2 {
					t.Errorf("%v: expected at least %v bytes uploaded but got %v", i, rawData/2, uploaded)
				}
			}
			// Check the stats of iteration 2.
			if i == 1 {
				// No data downloaded in this test.
				if downloaded != 0 {
					t.Errorf("%v: expected %v bytes downloaded but got %v", i, 0, downloaded)
				}
				// Uploaded succeeded so all data was uploaded.
				if uploaded != rawData {
					t.Errorf("%v: expected %v bytes uploaded but got %v", i, rawData, uploaded)
				}
			}
			// Close the stream.
			if err := stream.Close(); err != nil {
				t.Error(err)
				return
			}
		}
	}
	// Spin up the threads.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientWorker()
	}()
	go func() {
		defer wg.Done()
		serverWorker()
	}()
	// Wait for client and server threads to be done.
	close(start)
	wg.Wait()
}

// TestBandwidthLimit_RecordUpload tests setting a upload limit.
func TestBandwidthLimit_RecordUpload(t *testing.T) {
	client, server := createTestingMuxs()
	defer client.Close()
	defer server.Close()
	numFrames := uint64(10)
	frameSize := uint64(client.settings.MaxFrameSize())
	maxPayload := maxFramePayloadSize(client.settings.MaxFrameSize(), client.staticAead) - marshaledFrameHeaderSize
	data := fastrand.Bytes(maxPayload * int(numFrames))
	rawData := numFrames * frameSize

	start := make(chan struct{})
	// Server thread.
	serverWorker := func() {
		<-start
		// Wait for a stream.
		stream, err := server.AcceptStream()
		if err != nil {
			t.Error(err)
			return
		}
		// Read some data.
		readData := make([]byte, len(data))
		_, err = io.ReadFull(stream, readData)
		if err != nil {
			t.Error(err)
			return
		}
		// Set the upload limit to be half the length of the expected data.
		// This way we receive some frames before the limit is reached and also
		// afterwards.
		l := newTestLimit(math.MaxUint64, rawData/2)
		err = stream.SetLimit(l)
		if err != nil {
			t.Error(err)
			return
		}
		// Write some data. This should fail.
		_, err = stream.Write(data)
		if !errors.Contains(err, errUploadLimitReached) {
			t.Error(err)
			return
		}
		// Check uploaded bytes.
		if l.Uploaded() != rawData/2 {
			t.Errorf("expected %v uploaded bytes but got %v", rawData/2, l.Uploaded())
		}
		// Wait for another stream without closing the initial one. That way we
		// make sure that a triggered limit will correctly unblock the peer.
		stream, err = server.AcceptStream()
		if err != nil {
			t.Error(err)
			return
		}
		// Read some data.
		_, err = io.ReadFull(stream, readData)
		if err != nil {
			t.Error(err)
			return
		}
		// Set the upload limit to be exactly the length of the expected data.
		l = newTestLimit(math.MaxUint64, rawData)
		err = stream.SetLimit(l)
		if err != nil {
			t.Error(err)
			return
		}
		// Write some data. This should pass.
		_, err = stream.Write(data)
		if err != nil {
			t.Error(err)
			return
		}
		// Check uploaded bytes.
		if l.Uploaded() != rawData {
			t.Errorf("expected %v uploaded bytes but got %v", rawData, l.Uploaded())
		}
		// Close the stream.
		if err := stream.Close(); err != nil {
			t.Error(err)
			return
		}
	}
	// Client thread.
	clientWorker := func() {
		<-start
		// Create a new stream.
		stream, err := client.NewStream()
		if err != nil {
			t.Error(err)
			return
		}
		// Write some data.
		_, err = stream.Write(data)
		if err != nil {
			t.Error(err)
			return
		}
		// Read some data.
		readData := make([]byte, len(data))
		_, err = io.ReadFull(stream, readData)
		// The read passes with half the read data.
		if err == nil {
			t.Error(err)
			return
		}
		// Check the stats.
		limit := stream.Limit()
		downloaded := limit.Downloaded()
		uploaded := limit.Uploaded()
		// The host limited the upload to half the data. So the renter
		// received half of it.
		if downloaded != rawData/2 {
			t.Errorf("Expected at least %v bytes downloaded but got %v", rawData/2, downloaded)
		}
		// All data is uploaded on success.
		if uploaded != rawData {
			t.Errorf("Expected %v bytes uploaded but got %v", rawData, uploaded)
		}
		// Close the stream.
		if err := stream.Close(); err != nil {
			t.Error(err)
			return
		}
		// Create a new stream.
		stream, err = client.NewStream()
		if err != nil {
			t.Error(err)
			return
		}
		// Write some data.
		_, err = stream.Write(data)
		if err != nil {
			t.Error(err)
			return
		}
		// Read some data.
		_, err = io.ReadFull(stream, readData)
		if err != nil {
			t.Error(err)
			return
		}
		// Check the stats again.
		limit = stream.Limit()
		downloaded = limit.Downloaded()
		uploaded = limit.Uploaded()
		// All data is downloaded on success.
		if downloaded != rawData {
			t.Errorf("Expected %v bytes downloaded but got %v", rawData, downloaded)
		}
		// All data is uploaded on success.
		if uploaded != rawData {
			t.Errorf("Expected %v bytes uploaded but got %v", rawData, uploaded)
		}
		// Close the stream.
		if err := stream.Close(); err != nil {
			t.Error(err)
			return
		}
	}
	// Spin up the threads.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientWorker()
	}()
	go func() {
		defer wg.Done()
		serverWorker()
	}()
	// Wait for client and server threads to be done.
	close(start)
	wg.Wait()
}

// TestStream_SetLimit tests that setting a new limit correctly carries over the
// old limit's values.
func TestStream_SetLimit(t *testing.T) {
	t.Parallel()
	client, server := createTestingMuxs()

	go func() {
		stream, err := client.NewStream()
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = stream.Write([]byte{1, 2, 3})
	}()

	// Accept a stream.
	stream, err := server.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	// Check the current download and upload values.
	down, up := stream.Limit().Downloaded(), stream.Limit().Uploaded()
	// Record more data.
	deltaDown, deltaUp := fastrand.Uint64n(100)+1, fastrand.Uint64n(100)+1
	err = stream.managedRecordDownload(deltaDown)
	if err != nil {
		t.Fatal(err)
	}
	err = stream.managedRecordUpload(deltaUp)
	if err != nil {
		t.Fatal(err)
	}
	// Values should have increased.
	newDown, newUp := stream.Limit().Downloaded(), stream.Limit().Uploaded()
	if newDown != down+deltaDown || newUp != up+deltaUp {
		t.Fatalf("unexpected values: %v != %v || %v != %v", newDown, down+deltaDown, newUp, up+deltaUp)
	}
	// Replace the limit with a new one.
	tl := newTestLimit(math.MaxUint64, math.MaxUint64)
	err = stream.SetLimit(tl)
	if err != nil {
		t.Fatal(err)
	}
	// Values should still be the same.
	if newDown != tl.Downloaded() {
		t.Fatalf("%v != %v", newDown, tl.Downloaded())
	}
	if newUp != tl.Uploaded() {
		t.Fatalf("%v != %v", newUp, tl.Uploaded())
	}
}

// TestDynamicFrameSizeBandwidth tests sending a single frame with any possible
// number of allowed packets and makes sure that the bandwidthLimit tracks those
// bytes correctly.
func TestDynamicFrameSizeBandwidth(t *testing.T) {
	client, server := createTestingMuxs()
	defer client.Close()
	defer server.Close()

	// Get some vars before starting the test.
	aead := client.staticAead
	packetSize := client.settings.RequestedPacketSize
	maxFrameSizePackets := client.settings.MaxFrameSizePackets

	// Declare a helper to get the expected bytes required to encode a payload.
	requiredBytes := func(payloadLen uint64) uint64 {
		encryptedFrameSize := marshaledFrameHeaderSize + payloadLen + uint64(2*aead.NonceSize()+2*aead.Overhead())
		numPackets := encryptedFrameSize / uint64(packetSize)
		if encryptedFrameSize%uint64(packetSize) != 0 {
			numPackets++
		}
		return numPackets * uint64(packetSize)
	}

	// Declare the test.
	run := func(payloadLen uint64) {
		data := fastrand.Bytes(int(payloadLen))

		start := make(chan struct{})
		// Server thread.
		serverWorker := func() {
			<-start
			// Wait for a stream.
			stream, err := server.AcceptStream()
			if err != nil {
				t.Error(err)
				return
			}
			// Read some data.
			readData := make([]byte, len(data))
			_, err = io.ReadFull(stream, readData)
			if err != nil {
				t.Error(err)
				return
			}
			// Make sure we read the right amount of data.
			downloaded := stream.Limit().Downloaded()
			if downloaded != requiredBytes(payloadLen) {
				t.Errorf("expected %v downloaded bytes but got %v", downloaded, requiredBytes(payloadLen))
			}
			// Close the stream.
			if err := stream.Close(); err != nil {
				t.Error(err)
				return
			}
		}
		// Client thread.
		clientWorker := func() {
			<-start
			// Create a new stream.
			stream, err := client.NewStream()
			if err != nil {
				t.Error(err)
				return
			}
			// Write some data.
			_, err = stream.Write(data)
			if err != nil {
				t.Error(err)
				return
			}
			// Make sure we write the right amount of data.
			uploaded := stream.Limit().Uploaded()
			if uploaded != requiredBytes(payloadLen) {
				t.Errorf("expected %v uploaded bytes but got %v", uploaded, requiredBytes(payloadLen))
			}
			// Close the stream.
			if err := stream.Close(); err != nil {
				t.Error(err)
				return
			}
		}
		// Run the threads.
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			serverWorker()
		}()
		go func() {
			defer wg.Done()
			clientWorker()
		}()
		close(start)
		wg.Wait()
	}

	// Increase the payload size in random steps. That way we run the test at
	// least once for any number of possible packets from [1;10]
	payloadSize := uint64(1)
	for payloadSize < uint64(maxFrameSizePackets)*uint64(packetSize) {
		run(payloadSize)
		payloadSize += fastrand.Uint64n(uint64(packetSize))
	}
}
