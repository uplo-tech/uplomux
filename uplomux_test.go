package uplomux

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uplo-tech/errors"
	"github.com/uplo-tech/fastrand"
	"github.com/uplo-tech/log"
	"github.com/uplo-tech/uplomux/helpers"
	"github.com/uplo-tech/uplomux/mux"
)

type muxTester struct {
	*UploMux
}

func testDir(name string) string {
	return filepath.Join(helpers.TestDir(name))
}

// publicKey returns the server's public key used to sign the initial handshake.
func (mt *muxTester) publicKey() mux.ED25519PublicKey {
	return mt.staticPubKey
}

// newMuxTester creates a new UploMux which is ready to be used.
func newMuxTester(testDir string) (*muxTester, error) {
	path := filepath.Join(testDir, helpers.RandomSuffix())
	sm, err := New("127.0.0.1:0", "127.0.0.1:0", log.DiscardLogger, path)
	if err != nil {
		return nil, err
	}
	return &muxTester{
		UploMux: sm,
	}, nil
}

// newMuxTesterPair returns two new mux testers.
func newMuxTesterPair(name string) (client, server *muxTester) {
	// Create a client and a server.
	client, err := newMuxTester(testDir(name + "_client"))
	if err != nil {
		panic(err)
	}
	server, err = newMuxTester(testDir(name + "_server"))
	if err != nil {
		panic(err)
	}
	return client, server
}

// TestNewUploMux confirms that creating and closing a UploMux works as expected.
func TestNewUploMux(t *testing.T) {
	// Create UploMux.
	sm, err := newMuxTester(testDir(t.Name()))
	if err != nil {
		t.Fatal(err)
	}
	// Check if the appSeed was set.
	if sm.staticAppSeed == 0 {
		t.Error("appSeed is 0")
	}
	// Close it again.
	if err := sm.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestNewStream tests if registering a listener and connecting to it works as
// expected.
func TestNewStream(t *testing.T) {
	// Run test with tcp conn.
	t.Run("TCP", func(t *testing.T) {
		client, server := newMuxTesterPair(t.Name())
		defer client.Close()
		defer server.Close()
		testNewStream(t, client, server, server.Address().String())
	})
	// Run test with websocket.
	t.Run("WS", func(t *testing.T) {
		client, server := newMuxTesterPair(t.Name())
		defer client.Close()
		defer server.Close()
		testNewStream(t, client, server, server.URL())
	})
}

// testNewStream test if registering a listener and connecting to it works as
// expected. The client will use srvAddr to connect to.
func testNewStream(t *testing.T, client, server *muxTester, srvAddr string) {
	// Prepare a handler to be registered by the server.
	var numHandlerCalls uint64
	handler := func(stream Stream) {
		atomic.AddUint64(&numHandlerCalls, 1)
		// Close the stream after handling it.
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
	}
	// Create an ephemeral stream.
	ephemeralStream, err := client.NewEphemeralStream("test", srvAddr, DefaultNewStreamTimeout, server.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	// Call write to get subscriber request out.
	_, err = ephemeralStream.Write(fastrand.Bytes(1))
	if err != nil {
		t.Fatal(err)
	}
	_, err = ephemeralStream.Read(make([]byte, 1))
	if err == nil || !strings.Contains(err.Error(), errUnknownSubscriber.Error()) {
		t.Fatal("error should be errUnknownSubscriber but was:", err)
	}
	// There should be 1 open mux.
	err = client.assertNumMuxs(1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Close the stream.
	if err := ephemeralStream.Close(); err != nil {
		t.Fatal(err)
	}
	// Now there should be 0 muxs.
	err = client.assertNumMuxs(0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Try creating a new stream.
	stream, err := client.NewStream("test", srvAddr, server.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	// Call write to get subscriber request out.
	_, err = stream.Write(fastrand.Bytes(1))
	if err != nil {
		t.Fatal(err)
	}
	_, err = stream.Read(make([]byte, 1))
	if err == nil || !strings.Contains(err.Error(), errUnknownSubscriber.Error()) {
		t.Fatal("error should be errUnknownSubscriber but was:", err)
	}
	if err := client.assertNumMuxs(1, 1, 1); err != nil {
		t.Fatal(err)
	}
	// Try creating a new ephemeral stream.
	ephemeralStream, err = client.NewEphemeralStream("test", srvAddr, DefaultNewStreamTimeout, server.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	// Call write to get subscriber request out.
	_, err = ephemeralStream.Write(fastrand.Bytes(1))
	if err != nil {
		t.Fatal(err)
	}
	_, err = ephemeralStream.Read(make([]byte, 1))
	if err == nil || !strings.Contains(err.Error(), errUnknownSubscriber.Error()) {
		t.Fatal("error should be errUnknownSubscriber but was:", err)
	}
	// The number of muxs should be the same since we are reusing an existing
	// one.
	err = client.assertNumMuxs(1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Register a listener.
	if err := server.NewListener("test", handler); err != nil {
		t.Fatal(err)
	}
	if len(server.handlers) != 1 {
		t.Fatalf("expected %v handler but got %v", 1, len(server.handlers))
	}
	// Try creating a new stream again. This time it should work.
	stream, err = client.NewStream("test", srvAddr, server.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	// Check the fields of client and server. The client still has 1 mux since
	// it's reusing the already open one.
	if err := client.assertNumMuxs(1, 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := server.assertNumMuxs(1, 1, 0); err != nil {
		t.Fatal(err)
	}
	// Try creating one more ephemeral stream. This time the listener exists.
	ephemeralStream, err = client.NewEphemeralStream("test", srvAddr, DefaultNewStreamTimeout, server.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	// The number of muxs should be unchanged since we are reusing an existing
	// one.
	err = client.assertNumMuxs(1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Close the stream.
	if err := ephemeralStream.Close(); err != nil {
		t.Fatal(err)
	}
	// The number of muxs should still be unchanged since we reused an existing
	// one.
	err = client.assertNumMuxs(1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Call write to get subscriber request out.
	_, err = stream.Write(fastrand.Bytes(1))
	if err != nil {
		t.Fatal(err)
	}
	// Check if the handler has been called exactly once so far. Need to do this
	// in a retry to avoid NDFs.
	err = helpers.Retry(100, 100*time.Millisecond, func() error {
		if numCalls := atomic.LoadUint64(&numHandlerCalls); numCalls != 1 {
			return fmt.Errorf("handler should've been called once but was %v", numCalls)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Delete the listener again. The stream should be closed.
	if err := server.CloseListener("test"); err != nil {
		t.Fatal(err)
	}
	if len(server.handlers) != 0 {
		t.Fatalf("expected %v handler but got %v", 0, len(server.handlers))
	}
	// Try creating a new stream one last time. This should fail with errUnknownSubscriber
	// since the server unregistered the handler.
	stream, err = client.NewStream("test", srvAddr, server.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	// Call write to get subscriber request out.
	_, err = stream.Write(fastrand.Bytes(1))
	if err != nil {
		t.Fatal(err)
	}
	_, err = stream.Read(make([]byte, 1))
	if err == nil || !strings.Contains(err.Error(), errUnknownSubscriber.Error()) {
		t.Fatal("error should be errUnknownSubscriber but was:", err)
	}
	// Close the stream.
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	// Check if the handler has been called exactly once again.
	if numCalls := atomic.LoadUint64(&numHandlerCalls); numCalls != 1 {
		t.Fatalf("handler should've been called once but was %v", numCalls)
	}
	// The server should still have 1 mux.
	if err := server.assertNumMuxs(1, 1, 0); err != nil {
		t.Fatal(err)
	}
	// Simulate a timeout by closing the server's mux.
	for _, mux := range server.muxs {
		if err := mux.Close(); err != nil {
			t.Fatal(err)
		}
	}
	// The server should be back to having 0 muxs since closing the mux caused
	// it to remove it from the UploMux.
	if err := server.assertNumMuxs(0, 0, 0); err != nil {
		t.Fatal(err)
	}
	// Since the server terminated the connection, the client should also be
	// cleaned up.
	err = helpers.Retry(100, 100*time.Millisecond, func() error {
		return client.assertNumMuxs(0, 0, 0)
	})
	if err != nil {
		t.Error(err)
	}
}

// TestMultiStream tests that multiple streams talking over the same mux can all
// send frames at the same time, and all receive the expected data.
func TestMultiStream(t *testing.T) {
	// Run test with tcp conn.
	t.Run("TCP", func(t *testing.T) {
		client, server := newMuxTesterPair(t.Name())
		defer client.Close()
		defer server.Close()
		testMultiStream(t, client, server, server.Address().String())
	})
	// Run test with websocket.
	t.Run("WS", func(t *testing.T) {
		client, server := newMuxTesterPair(t.Name())
		defer client.Close()
		defer server.Close()
		testMultiStream(t, client, server, server.URL())
	})
}

// testMultiStream tests that multiple streams talking over the same mux can all
// send frames at the same time, and all receive the expected data.
func testMultiStream(t *testing.T, client, server *muxTester, srvAddr string) {
	// Create handlers for the streams on the server. Each handler reads an
	// expected set of bytes and then closes. Each handler is a dramatically
	// different size, meaning that they handle different sized frames and
	// different numbers of frames.
	handler1msg := fastrand.Bytes(fastrand.Intn(10) + 1)
	handler1resp := fastrand.Bytes(fastrand.Intn(10) + 1)
	handler2msg := fastrand.Bytes(fastrand.Intn(1e3) + 1)
	handler2resp := fastrand.Bytes(fastrand.Intn(1e3) + 1)
	handler3msg := fastrand.Bytes(fastrand.Intn(10e3) + 1)
	handler3resp := fastrand.Bytes(fastrand.Intn(10e3) + 1)
	handler4msg := fastrand.Bytes(fastrand.Intn(2e6) + 1)
	handler4resp := fastrand.Bytes(fastrand.Intn(2e6) + 1)
	handler1 := func(stream Stream) {
		defer func() {
			err := stream.Close()
			if err != nil {
				t.Error(err)
			}
		}()
		readBuf := make([]byte, len(handler1msg))
		_, err := io.ReadFull(stream, readBuf)
		if err != nil {
			t.Error(err)
			return
		}
		if !bytes.Equal(readBuf, handler1msg) {
			t.Error("unexpected mismatch")
			return
		}
		_, err = stream.Write(handler1resp)
		if err != nil {
			t.Error(err)
			return
		}
	}
	handler2 := func(stream Stream) {
		defer func() {
			err := stream.Close()
			if err != nil {
				t.Error(err)
			}
		}()
		readBuf := make([]byte, len(handler2msg))
		_, err := io.ReadFull(stream, readBuf)
		if err != nil {
			t.Error(err)
			return
		}
		if !bytes.Equal(readBuf, handler2msg) {
			t.Error("unexpected mismatch")
			return
		}
		_, err = stream.Write(handler2resp)
		if err != nil {
			t.Error(err)
			return
		}
	}
	handler3 := func(stream Stream) {
		defer func() {
			err := stream.Close()
			if err != nil {
				t.Error(err)
			}
		}()
		readBuf := make([]byte, len(handler3msg))
		_, err := io.ReadFull(stream, readBuf)
		if err != nil {
			t.Error(err)
			return
		}
		if !bytes.Equal(readBuf, handler3msg) {
			t.Error("unexpected mismatch")
			return
		}
		_, err = stream.Write(handler3resp)
		if err != nil {
			t.Error(err)
			return
		}
	}
	handler4 := func(stream Stream) {
		defer func() {
			err := stream.Close()
			if err != nil {
				t.Error(err)
			}
		}()
		readBuf := make([]byte, len(handler4msg))
		_, err := io.ReadFull(stream, readBuf)
		if err != nil {
			t.Error(err)
			return
		}
		if !bytes.Equal(readBuf, handler4msg) {
			t.Log()
			return
		}
		_, err = stream.Write(handler4resp)
		if err != nil {
			t.Error(err)
			return
		}
	}

	// Register all handlers to the server.
	err := server.NewListener("1", handler1)
	if err != nil {
		t.Fatal(err)
	}
	err = server.NewListener("2", handler2)
	if err != nil {
		t.Fatal(err)
	}
	err = server.NewListener("3", handler3)
	if err != nil {
		t.Fatal(err)
	}
	err = server.NewListener("4", handler4)
	if err != nil {
		t.Fatal(err)
	}

	// randomStream is a helper function to create either an ephemeral or
	// regular stream with the server.
	randomStream := func(subscriber string) (Stream, error) {
		if fastrand.Intn(2) == 0 {
			return client.NewEphemeralStream(subscriber, srvAddr, DefaultNewStreamTimeout, server.publicKey())
		}
		return client.NewStreamTimeout(subscriber, srvAddr, DefaultNewStreamTimeout, server.publicKey())
	}

	// Create the sender methods.
	sender1 := func() {
		stream, err := randomStream("1")
		if err != nil {
			t.Error(err)
			return
		}
		_, err = stream.Write(handler1msg)
		if err != nil {
			t.Error(err)
			return
		}
		readBuf := make([]byte, len(handler1resp))
		_, err = io.ReadFull(stream, readBuf)
		if err != nil {
			t.Error(err)
			return
		}
		if !bytes.Equal(readBuf, handler1resp) {
			t.Error("mismatch")
			return
		}
		err = stream.Close()
		if err != nil {
			t.Error(err)
		}
	}
	sender2 := func() {
		stream, err := randomStream("2")
		if err != nil {
			t.Error(err)
			return
		}
		_, err = stream.Write(handler2msg)
		if err != nil {
			t.Error(err)
			return
		}
		readBuf := make([]byte, len(handler2resp))
		_, err = io.ReadFull(stream, readBuf)
		if err != nil {
			t.Error(err)
			return
		}
		if !bytes.Equal(readBuf, handler2resp) {
			t.Error("mismatch")
			return
		}
		err = stream.Close()
		if err != nil {
			t.Error(err)
		}
	}
	sender3 := func() {
		stream, err := randomStream("3")
		if err != nil {
			t.Error(err)
			return
		}
		_, err = stream.Write(handler3msg)
		if err != nil {
			t.Error(err)
			return
		}
		readBuf := make([]byte, len(handler3resp))
		_, err = io.ReadFull(stream, readBuf)
		if err != nil {
			t.Error(err)
			return
		}
		if !bytes.Equal(readBuf, handler3resp) {
			t.Error("mismatch")
			return
		}
		err = stream.Close()
		if err != nil {
			t.Error(err)
		}
	}
	sender4 := func() {
		stream, err := randomStream("4")
		if err != nil {
			t.Error(err)
			return
		}
		_, err = stream.Write(handler4msg)
		if err != nil {
			t.Error(err)
			return
		}
		readBuf := make([]byte, len(handler4resp))
		_, err = io.ReadFull(stream, readBuf)
		if err != nil {
			t.Error(err)
			return
		}
		if !bytes.Equal(readBuf, handler4resp) {
			t.Error("mismatch")
			return
		}
		err = stream.Close()
		if err != nil {
			t.Error(err)
		}
	}

	// Verify that without concurrency, all of the sender methods work.
	sender1()
	sender2()
	sender3()
	sender4()

	// Spin up multiple goroutines per handler to continuously send frames down
	// the mux.
	var wg sync.WaitGroup
	threadsPerSender := 3
	sendsPerSender := int(1e3)
	start := make(chan struct{})
	for i := 0; i < threadsPerSender; i++ {
		wg.Add(1)
		go func() {
			<-start
			defer wg.Done()
			for i := 0; i < sendsPerSender; i++ {
				sender1()
			}
		}()
	}
	for i := 0; i < threadsPerSender; i++ {
		wg.Add(1)
		go func() {
			<-start
			defer wg.Done()
			for i := 0; i < sendsPerSender/2; i++ {
				sender2()
			}
		}()
	}
	for i := 0; i < threadsPerSender; i++ {
		wg.Add(1)
		go func() {
			<-start
			defer wg.Done()
			for i := 0; i < sendsPerSender/5; i++ {
				sender3()
			}
		}()
	}
	for i := 0; i < threadsPerSender; i++ {
		wg.Add(1)
		go func() {
			<-start
			defer wg.Done()
			for i := 0; i < sendsPerSender/20; i++ {
				sender4()
			}
		}()
	}
	close(start)
	wg.Wait()

	// Both uplomuxs should only contain a single mux each.
	if err := client.assertNumMuxs(1, 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := server.assertNumMuxs(1, 1, 0); err != nil {
		t.Fatal(err)
	}
	var clientMux, serverMux muxInfo
	for _, mux := range client.muxSet {
		clientMux = mux
		break
	}
	for _, mux := range server.muxSet {
		serverMux = mux
		break
	}
	if len(clientMux.addresses) != 1 {
		t.Fatal("client should have 1 address: ", len(clientMux.addresses))
	}
	if len(serverMux.addresses) != 0 {
		t.Fatal("server should have 0 addresses: ", len(serverMux.addresses))
	}

	// Cleanly close muxs.
	err = client.Close()
	if err != nil {
		t.Error(err)
	}
	err = server.Close()
	if err != nil {
		t.Error(err)
	}
}

// TestTimeoutCallback makes sure the timeout callback methods are triggered
// correctly.
func TestTimeoutCallback(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	mux.DefaultMaxTimeout = 5
	mux.LowerMaxTimeout = 0
	mux.DefaultMaxStreamTimeout = 3
	mux.TimeoutNotificationBuffer = time.Duration(4 * time.Second)

	// Create 2 UploMuxs and have one of them connect to the other one.
	client, err := newMuxTester(testDir(t.Name()))
	if err != nil {
		t.Fatal(err)
	}
	server, err := newMuxTester(testDir(t.Name()))
	if err != nil {
		t.Fatal(err)
	}

	// Prepare a handler to be registered by the server.
	data := fastrand.Bytes(10)
	handler := func(stream Stream) {
		// Read some data from the stream.
		d := make([]byte, len(data))
		_, err := stream.Read(d)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(d, data) {
			t.Errorf("data doesn't match")
		}
		// Close the stream after handling it.
		if err := stream.Close(); err != nil {
			t.Error(err)
		}
	}
	if err := server.NewListener("test", handler); err != nil {
		t.Fatal(err)
	}
	// Try creating a new stream. This should fail with errUnknownSubscriber
	// since the server hasn't registered a handler yet.
	stream, err := client.NewStream("test", server.Address().String(), server.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	// Write some data to the stream to make sure it's established.
	_, err = stream.Write(data)
	if err != nil {
		t.Fatal(err)
	}
	// Wait for 5 times the max timeout without writing or reading to make sure
	// the connection is kept alive.
	time.Sleep(5 * time.Duration(mux.DefaultMaxTimeout) * time.Second)
	// The mux should still be in outgoingMuxs
	client.staticMu.Lock()
	m, exists := client.outgoingMuxs[server.Address().String()]
	client.staticMu.Unlock()
	if !exists {
		t.Fatal("outgoing mux doesn't exist anymore")
	}
	// Directly use the mux to check if it's still working.
	stream, err = m.NewStream()
	if err != nil {
		t.Fatal(err)
	}
	// Write to the stream. This should still work.
	_, err = stream.Write(data)
	if err != nil {
		t.Fatal(err)
	}
}

// BenchmarkStreamThroughput tests the throughput of multiple threads sending
// data to a mux.
//
// Results
//
// 16 threads - i9 - Commit f69100d0d09b561e3819bfcd5b7802b562b4d5ca
//   TCP: 47.12 MB/s
//   WS : 27.98 MB/s
//
func BenchmarkStreamThroughput(b *testing.B) {
	b.Run("TCP", func(b *testing.B) {
		client, server := newMuxTesterPair(b.Name())
		defer client.Close()
		defer server.Close()
		benchmarkStreamThroughput(b, client, server, server.Address().String())
	})
	b.Run("WS", func(b *testing.B) {
		client, server := newMuxTesterPair(b.Name())
		defer client.Close()
		defer server.Close()
		benchmarkStreamThroughput(b, client, server, server.URL())
	})
}

// benchmarkStreamThroughput is the subtest run by BenchmarkStreamThroughput.
func benchmarkStreamThroughput(b *testing.B, client, server *muxTester, srvAddr string) {
	// Prepare a handler to be registered by the server.
	handler := func(stream Stream) {
		// Read from the stream.
		_, err := io.Copy(ioutil.Discard, stream)
		if errors.Contains(err, io.ErrClosedPipe) {
			return // shutdown
		}
		if err != nil {
			b.Error(err)
		}
	}
	if err := server.NewListener("test", handler); err != nil {
		b.Fatal(err)
	}

	// Declare some vars.
	numThreads := runtime.NumCPU()
	bytesPerOperation := numThreads * 10 * 1 << 20 // 10 MiB * numThreads
	b.SetBytes(int64(bytesPerOperation))
	data := fastrand.Bytes(bytesPerOperation)

	// Declare the sending thread.
	start := make(chan struct{})
	sender := func(stream Stream) {
		<-start
		// Write data
		for i := 0; i < b.N; i++ {
			_, err := stream.Write(data)
			if err != nil {
				b.Error(err)
				return
			}
		}
		// Close the stream.
		err := stream.Close()
		if err != nil {
			b.Error(err)
			return
		}
	}

	// start pool
	var wg sync.WaitGroup
	for i := 0; i < numThreads; i++ {
		// Connect to the server.
		stream, err := client.NewStream("test", srvAddr, server.publicKey())
		if err != nil {
			b.Fatal(err)
			return
		}
		wg.Add(1)
		go func() {
			sender(stream)
			wg.Done()
		}()
	}

	// reset timer
	b.ResetTimer()

	// start the threads
	close(start)

	// wait for them to finish
	wg.Wait()

	// log some info
	b.Logf("Ran test with %v threads", numThreads)
}

// TestAppSeedDerivation tests that both the client and server store the mux
// using the correct appSeed.
func TestAppSeedDerivation(t *testing.T) {
	// Create 2 UploMuxs and have one of them connect to the other one.
	client, err := newMuxTester(testDir(t.Name()))
	if err != nil {
		t.Fatal(err)
	}
	server, err := newMuxTester(testDir(t.Name()))
	if err != nil {
		t.Fatal(err)
	}

	// Prepare a handler to be registered by the server.
	var numHandlerCalls uint64
	handler := func(stream Stream) {
		atomic.AddUint64(&numHandlerCalls, 1)
		// Close the stream after handling it.
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
	}
	// Register a listener.
	if err := server.NewListener("test", handler); err != nil {
		t.Fatal(err)
	}
	if len(server.handlers) != 1 {
		t.Fatalf("expected %v handler but got %v", 1, len(server.handlers))
	}
	// Create a stream.
	stream, err := client.NewStream("test", server.Address().String(), server.publicKey())
	if err != nil {
		t.Fatal(err)
	}

	// Write some data to establish the stream on the server.
	_, err = stream.Write([]byte{1})
	if err != nil {
		t.Fatal(err)
	}

	// Both UploMuxs should store a single mux with the same appSeed.
	clientSeed, err := deriveEphemeralAppSeed(client.staticAppSeed, server.Address())
	if err != nil {
		t.Fatal(err)
	}
	serverSeed, err := deriveEphemeralAppSeed(server.staticAppSeed, client.Address())
	if err != nil {
		t.Fatal(err)
	}
	expectedSeed := clientSeed + serverSeed

	_, exists := client.muxs[expectedSeed]
	if !exists {
		t.Fatal("client doesn't contain expected seed", expectedSeed)
	}
	_, exists = server.muxs[expectedSeed]
	if !exists {
		t.Fatal("server doesn't contain expected seed", expectedSeed)
	}
}

// testMuxCleanupOnDisconnect makes sure that a mux disconnecting from another
// mux will correctly clean up the other mux.
func testMuxCleanupOnDisconnect(t *testing.T, closeServer bool) {
	// Create 2 UploMuxs and have one of them connect to the other one.
	client, err := newMuxTester(testDir(t.Name()))
	if err != nil {
		t.Fatal(err)
	}
	server, err := newMuxTester(testDir(t.Name()))
	if err != nil {
		t.Fatal(err)
	}

	// Prepare a handler to be registered by the server.
	var numHandlerCalls uint64
	handler := func(stream Stream) {
		atomic.AddUint64(&numHandlerCalls, 1)
		// Close the stream after handling it.
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
	}
	// Register a listener.
	if err := server.NewListener("test", handler); err != nil {
		t.Fatal(err)
	}
	if len(server.handlers) != 1 {
		t.Fatalf("expected %v handler but got %v", 1, len(server.handlers))
	}
	// Create a new stream.
	stream, err := client.NewStream("test", server.Address().String(), server.publicKey())
	if err != nil {
		t.Fatal(err)
	}

	// Write some data to establish the stream on the server.
	_, err = stream.Write([]byte{1})
	if err != nil {
		t.Fatal(err)
	}

	// Check client and server muxs.
	err = client.assertNumMuxs(1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	err = server.assertNumMuxs(1, 1, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Close either the server or client mux.
	if closeServer {
		err = server.Close()
	} else {
		err = client.Close()
	}
	if err != nil {
		t.Fatal(err)
	}

	// Check client and server muxs again.
	err = helpers.Retry(100, time.Millisecond*100, func() error {
		if err := client.assertNumMuxs(0, 0, 0); err != nil {
			return err
		}
		if err := server.assertNumMuxs(0, 0, 0); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestMuxCleanupOnDisconnect makes sure that a mux disconnecting from another
// mux will correctly clean up the other mux.
func TestMuxCleanupOnDisconnect(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	t.Run("Server", func(t *testing.T) {
		testMuxCleanupOnDisconnect(t, true)
	})
	t.Run("Client", func(t *testing.T) {
		testMuxCleanupOnDisconnect(t, false)
	})
}

// assertNumMuxs is a helper to assert the number of muxs stored in the free
// containers of the uplomux.
func (sm *UploMux) assertNumMuxs(muxs, muxSet, outgoingMuxs int) error {
	sm.staticMu.Lock()
	defer sm.staticMu.Unlock()
	if len(sm.muxs) != muxs {
		return fmt.Errorf("sm.muxs: expected %v but got %v", muxs, len(sm.muxs))
	}
	if len(sm.muxSet) != muxSet {
		return fmt.Errorf("sm.muxSet: expected %v but got %v", muxSet, len(sm.muxSet))
	}
	if len(sm.outgoingMuxs) != outgoingMuxs {
		return fmt.Errorf("sm.outgoingMuxs: expected %v but got %v", outgoingMuxs, len(sm.outgoingMuxs))
	}
	return nil
}

// TestNewEphemeralStreamEdgeCases runs a few tests which are meant to identify
// edge cases around the usage of the ephemeral stream.
func TestNewEphemeralStreamEdgeCases(t *testing.T) {
	t.Run("Multi-Ephemeral", func(t *testing.T) {
		client, server := newMuxTesterPair(t.Name())
		defer client.Close()
		defer server.Close()
		testNewEphemeralStreamEdgeCasesMultiEphemeral(t, client, server)
	})
	t.Run("Mixed", func(t *testing.T) {
		client, server := newMuxTesterPair(t.Name())
		defer client.Close()
		defer server.Close()
		testNewEphemeralStreamEdgeCasesMixed(t, client, server)
	})
	t.Run("EphemeralOnIdle", func(t *testing.T) {
		client, server := newMuxTesterPair(t.Name())
		defer client.Close()
		defer server.Close()
		testNewEphemeralStreamEdgeCasesEphemeralStreamOnIdleMux(t, client, server)
	})
}

// testNewEphemeralStreamEdgeCasesMultiEphemeral tests that using multiple
// ephemeral streams will only close the mux once the last one was closed.
func testNewEphemeralStreamEdgeCasesMultiEphemeral(t *testing.T, client, server *muxTester) {
	// Prepare a handler to be registered by the server.
	var numHandlerCalls uint64
	handler := func(stream Stream) {
		atomic.AddUint64(&numHandlerCalls, 1)
		// Close the stream after handling it.
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
	}

	// Register a listener.
	if err := server.NewListener("test", handler); err != nil {
		t.Fatal(err)
	}

	// Create 2 ephemeral streams.
	s1, err := client.NewEphemeralStream("test", server.Address().String(), DefaultNewStreamTimeout, server.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	s2, err := client.NewEphemeralStream("test", server.Address().String(), DefaultNewStreamTimeout, server.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	// Check the number of muxs on the uplomux.
	if err := client.assertNumMuxs(1, 1, 1); err != nil {
		t.Fatal(err)
	}

	// Close one ephemeral stream.
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}
	// Check the number of muxs on the uplomux. Should be the same as before.
	if err := client.assertNumMuxs(1, 1, 1); err != nil {
		t.Fatal(err)
	}

	// Close the other ephemeral stream.
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}
	// The mux should be gone now.
	if err := client.assertNumMuxs(0, 0, 0); err != nil {
		t.Fatal(err)
	}
}

// testNewEphemeralStreamEdgeCasesMixed makes sure that mixing ephemeral and
// regular streams won't close the mux.
func testNewEphemeralStreamEdgeCasesMixed(t *testing.T, client, server *muxTester) {
	// Prepare a handler to be registered by the server.
	var numHandlerCalls uint64
	handler := func(stream Stream) {
		atomic.AddUint64(&numHandlerCalls, 1)
		// Close the stream after handling it.
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
	}

	// Register a listener.
	if err := server.NewListener("test", handler); err != nil {
		t.Fatal(err)
	}

	// Create 1 ephemeral stream and 1 regular stream.
	ephemeralStream, err := client.NewEphemeralStream("test", server.Address().String(), DefaultNewStreamTimeout, server.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	regularStream, err := client.NewStreamTimeout("test", server.Address().String(), DefaultNewStreamTimeout, server.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	// Check the number of muxs on the uplomux.
	if err := client.assertNumMuxs(1, 1, 1); err != nil {
		t.Fatal(err)
	}

	// Close the regular stream.
	if err := regularStream.Close(); err != nil {
		t.Fatal(err)
	}
	// Check the number of muxs on the uplomux. Should be the same as before.
	if err := client.assertNumMuxs(1, 1, 1); err != nil {
		t.Fatal(err)
	}

	// Close the other ephemeral stream.
	if err := ephemeralStream.Close(); err != nil {
		t.Fatal(err)
	}
	// The mux should still be there.
	if err := client.assertNumMuxs(1, 1, 1); err != nil {
		t.Fatal(err)
	}
}

// testNewEphemeralStreamEdgeCasesEphemeralStreamOnIdleMux tests that creating
// an ephemeral stream on an idle mux won't close it afterwards.
func testNewEphemeralStreamEdgeCasesEphemeralStreamOnIdleMux(t *testing.T, client, server *muxTester) {
	// Prepare a handler to be registered by the server.
	var numHandlerCalls uint64
	handler := func(stream Stream) {
		atomic.AddUint64(&numHandlerCalls, 1)
		// Close the stream after handling it.
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
	}

	// Register a listener.
	if err := server.NewListener("test", handler); err != nil {
		t.Fatal(err)
	}

	// Create a regular stream.
	s, err := client.NewStreamTimeout("test", server.Address().String(), DefaultNewStreamTimeout, server.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	// Check the number of muxs on the uplomux.
	if err := client.assertNumMuxs(1, 1, 1); err != nil {
		t.Fatal(err)
	}
	// Close the stream.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Check the number of muxs on the uplomux. Should be the same.
	if err := client.assertNumMuxs(1, 1, 1); err != nil {
		t.Fatal(err)
	}

	// Create an ephemeral stream.
	s, err = client.NewEphemeralStream("test", server.Address().String(), DefaultNewStreamTimeout, server.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	// Check the number of muxs on the uplomux.
	if err := client.assertNumMuxs(1, 1, 1); err != nil {
		t.Fatal(err)
	}
	// Close the stream.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Check the number of muxs on the uplomux. Should be the same.
	if err := client.assertNumMuxs(1, 1, 1); err != nil {
		t.Fatal(err)
	}
}

// TestSetDeadlineDeadlock triggers a deadlock caused by a WSConn. It's a
// regression test to prevent it from reappearing.
func TestSetDeadlineDeadlock(t *testing.T) {
	client, server := newMuxTesterPair(t.Name())
	defer client.Close()
	defer server.Close()

	var wg sync.WaitGroup
	done := make(chan struct{})
	err := server.NewListener("test", func(stream Stream) {
		defer stream.Close()
		// Read the initial byte.
		_, err := stream.Read(make([]byte, 1))
		if err != nil {
			t.Error(err)
			return
		}
		// Start reading from stream.
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := stream.Read(make([]byte, 1))
			if err != nil {
				t.Error(err)
			}
		}()
		// Sleep for a bit to make sure the mux is blocking on the read.
		time.Sleep(time.Second)
		// Write a byte.
		_, err = stream.Write(make([]byte, 1))
		if err != nil {
			t.Fatal(err)
		}
		<-done
	})
	if err != nil {
		t.Fatal(err)
	}

	// Connect to the server using a websocket.
	stream, err := client.NewStream("test", server.staticURL, server.staticPubKey)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	// Write the initial byte to make sure the connection is established.
	_, err = stream.Write(make([]byte, 1))
	if err != nil {
		t.Fatal(err)
	}
	// Start reading from stream.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := stream.Read(make([]byte, 1))
		if err != nil {
			t.Error(err)
		}
	}()
	// Sleep for a bit to make sure the mux is blocking on the read.
	time.Sleep(time.Second)
	// Write a byte.
	_, err = stream.Write(make([]byte, 1))
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	close(done)
}

// TestBlockedStreamWriteError makes sure that a blocked stream will return the
// error of the initial blocking read upon write if available.
func TestBlockedStreamWriteError(t *testing.T) {
	client, server := newMuxTesterPair(t.Name())
	defer client.Close()
	defer server.Close()

	stream, err := client.NewStream("unknownSubscriber", server.Address().String(), server.staticPubKey)
	if err != nil {
		t.Fatal(err)
	}

	// Call write to get the subscriber request out.
	_, err = stream.Write([]byte{})
	if err != nil {
		t.Fatal(err)
	}

	// Wait a bit for the failed subscriber response to arrive.
	time.Sleep(time.Second)

	// Make sure Write returns the subscriber response error.
	_, err = stream.Write(make([]byte, 10))
	if err == nil || !strings.Contains(err.Error(), errUnknownSubscriber.Error()) {
		t.Fatal(err)
	}
}

// TestStreamReplacement tests multiple edge cases around duplicate muxs between
// two peers and makes sure the right muxs are closed when that happens.
func TestStreamReplacement(t *testing.T) {
	t.Run("Basic", testStreamReplacementBasic)
	t.Run("Renter", testStreamReplacementRenter)
	t.Run("Server", testStreamReplacementServer)
}

// testStreamReplacementBasic tests the case where both renter and server are
// aware that a duplicate mux exists and both agree on closing the "younger"
// one.
func testStreamReplacementBasic(t *testing.T) {
	t.Parallel()

	client, server := newMuxTesterPair(t.Name())
	defer client.Close()
	defer server.Close()

	// Register a listener that just keeps the connection open.
	block := make(chan struct{})
	err := server.NewListener("test", func(s Stream) {
		<-block
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a stream.
	stream, err := client.NewStream("test", server.Address().String(), server.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	// Check both client and server have a mux.
	err = client.assertNumMuxs(1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	err = server.assertNumMuxs(1, 1, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Grab the current mux on both the renter and client side.
	var muxOldClient, muxOldServer *mux.Mux
	for m := range client.muxSet {
		muxOldClient = m
		break
	}
	for m := range server.muxSet {
		muxOldServer = m
		break
	}

	// Create a new outgoing mux by calling managedNewOutgoingMux directly.
	om, err := client.managedNewOutgoingMux(server.Address().String(), time.Hour, server.PublicKey(), false)
	if err != nil {
		t.Fatal(err)
	}

	// Check both client and server have a mux.
	err = client.assertNumMuxs(1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	err = server.assertNumMuxs(1, 1, 0)
	if err != nil {
		t.Fatal(err)
	}

	// The returned mux should match the previous one.
	if om.Mux != muxOldClient {
		t.Fatal("client mux changed")
	}
	// The server should also still have the same mux.
	_, exists := server.muxSet[muxOldServer]
	if !exists {
		t.Fatal("server mux changed")
	}

	// Verify that we can create a new stream.
	stream, err = client.NewStream("test", server.Address().String(), server.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
}

// testStreamReplacementServer tests the edge case where a server "forgets"
// about an established mux and accepts a new connection attempt, but the client
// will instead reuse the existing mux.
func testStreamReplacementRenter(t *testing.T) {
	t.Parallel()

	client, server := newMuxTesterPair(t.Name())
	defer client.Close()
	defer server.Close()

	// Register a listener that just keeps the connection open.
	block := make(chan struct{})
	err := server.NewListener("test", func(s Stream) {
		<-block
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a stream.
	stream, err := client.NewStream("test", server.Address().String(), server.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	// Check both client and server have a mux.
	err = client.assertNumMuxs(1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	err = server.assertNumMuxs(1, 1, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Grab the current mux on both the renter and client side.
	var muxOldClient, muxOldServer *mux.Mux
	for m := range client.muxSet {
		muxOldClient = m
		break
	}
	for m := range server.muxSet {
		muxOldServer = m
		break
	}

	// Remove the mux from the server.
	server.staticMu.Lock()
	server.removeMux(muxOldServer)
	server.staticMu.Unlock()

	// Create a new outgoing mux by calling managedNewOutgoingMux directly.
	om, err := client.managedNewOutgoingMux(server.Address().String(), time.Hour, server.PublicKey(), false)
	if err != nil {
		t.Fatal(err)
	}

	// Wait a bit for the mux that was closed by the client to be removed from
	// the server since that happens asynchronously.
	time.Sleep(time.Second)

	// Check client has a mux but server doesn't cause client was reusing the
	// mux it knew of instead of creating a new one.
	err = client.assertNumMuxs(1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	err = server.assertNumMuxs(0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	// The returned mux should match the previous one.
	if om.Mux != muxOldClient {
		t.Fatal("client mux changed")
	}
	// The server should no longer have the same mux.
	_, exists := server.muxSet[muxOldServer]
	if exists {
		t.Fatal("server mux should've changed")
	}

	// Verify that we can create a new stream.
	stream, err = client.NewStream("test", server.Address().String(), server.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	// Number of muxs should still be the same.
	err = client.assertNumMuxs(1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	err = server.assertNumMuxs(0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
}

// testStreamReplacementServer tests the edge case where a client "forgets"
// about an established mux and has a new connection attempt to the server be
// rejected.
func testStreamReplacementServer(t *testing.T) {
	t.Parallel()

	client, server := newMuxTesterPair(t.Name())
	defer client.Close()
	defer server.Close()

	// Register a listener that just keeps the connection open.
	block := make(chan struct{})
	err := server.NewListener("test", func(s Stream) {
		<-block
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a stream.
	stream, err := client.NewStream("test", server.Address().String(), server.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	// Check both client and server have a mux.
	err = client.assertNumMuxs(1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	err = server.assertNumMuxs(1, 1, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Grab the current mux on the renter.
	var muxOldClient *mux.Mux
	for m := range client.muxSet {
		muxOldClient = m
		break
	}

	// Remove the mux from the client.
	client.staticMu.Lock()
	client.removeMux(muxOldClient)
	client.staticMu.Unlock()

	// The client should now no longer have a mux while the server does.
	err = client.assertNumMuxs(0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = server.assertNumMuxs(1, 1, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Create a new stream. This should fail cause the server rembers the mux and
	// will reject the new connection while the client won't and therefore can't
	// reuse the existing connection.
	_, err = client.NewStream("test", server.Address().String(), server.PublicKey())
	if err == nil || !strings.Contains(err.Error(), io.ErrClosedPipe.Error()) {
		t.Fatal(err)
	}
}

// TestNewStreamWithMux tests creating a stream from an established mux.
func TestNewStreamWithMux(t *testing.T) {
	// Create a pair of uplomux's for testing.
	client, server := newMuxTesterPair(t.Name())
	defer client.Close()
	defer server.Close()

	// Prepare a listener for the server.
	data := fastrand.Bytes(100) // some random data
	err := server.NewListener("server", func(stream Stream) {
		// Read data.
		b := make([]byte, len(data))
		_, err := io.ReadFull(stream, b)
		if err != nil {
			t.Fatal(err)
		}
		// Check that it's the correct data.
		if !bytes.Equal(data, b) {
			t.Fatal("server read wrong data")
		}
		// Open a response stream using a mux and send the data back.
		respStream, err := server.NewResponseStream("client", 0, stream)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := respStream.Close(); err != nil {
				t.Fatal(err)
			}
		}()
		_, err = respStream.Write(b)
		if err != nil {
			t.Fatal(err)
		}
	})
	if err != nil {
		t.Fatal(err)
	}

	// Prepare a listener for the client to count incoming streams.
	var wg sync.WaitGroup
	wg.Add(1)
	err = client.NewListener("client", func(stream Stream) {
		defer wg.Done()

		// Read data.
		b := make([]byte, len(data))
		_, err := io.ReadFull(stream, b)
		if err != nil {
			t.Fatal(err)
		}
		// Check that it's the correct data.
		if !bytes.Equal(data, b) {
			t.Fatal("server read wrong data")
		}
	})
	if err != nil {
		t.Fatal(err)
	}

	// The client connects to the server.
	stream, err := client.NewStream("server", server.staticListener.Addr().String(), server.staticPubKey)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	// Send data to the server.
	_, err = stream.Write(data)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for the response.
	wg.Wait()
}

// TestListenerCloseBlocking verifies that CloseListener won't return before
// running handlers are done.
func TestListenerCloseBlocking(t *testing.T) {
	t.Parallel()

	client, server := newMuxTesterPair(t.Name())
	defer client.Close()
	defer server.Close()

	// Prepare a handler to be registered by the server.
	var numHandlerCalls uint64
	block := make(chan struct{})
	handler := func(stream Stream) {
		// Read some data.
		buf := make([]byte, 1)
		_, err := io.ReadFull(stream, buf)
		if err != nil {
			t.Fatal(err)
		}
		// Close the stream after handling it.
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
		// Block handler from finishing.
		atomic.AddUint64(&numHandlerCalls, 1)
		<-block
	}

	// Launch async part of the test.
	done := make(chan struct{})
	go func() {
		defer close(done)

		// Register a listener.
		if err := server.NewListener("test", handler); err != nil {
			t.Error(err)
			return
		}
		// Create a new stream to trigger the handler.
		stream, err := client.NewStream("test", server.staticListener.Addr().String(), server.publicKey())
		if err != nil {
			t.Error(err)
			return
		}
		_, err = stream.Write(fastrand.Bytes(1))
		if err != nil {
			t.Error(err)
			return
		}

		// Wait for the listener to be called.
		err = helpers.Retry(100, 100*time.Millisecond, func() error {
			// The listener should have incremented the handler calls counter.
			nCalls := atomic.LoadUint64(&numHandlerCalls)
			if nCalls != 1 {
				return fmt.Errorf("wrong number of handler calls: %v", nCalls)
			}
			return nil
		})
		if err != nil {
			t.Error(err)
			return
		}

		// Close the listener.
		err = server.CloseListener("test")
		if err != nil {
			t.Error(err)
			return
		}
	}()

	// Wait for the listener to be called.
	err := helpers.Retry(100, 100*time.Millisecond, func() error {
		// The listener should have incremented the handler calls counter.
		nCalls := atomic.LoadUint64(&numHandlerCalls)
		if nCalls != 1 {
			return fmt.Errorf("wrong number of handler calls: %v", nCalls)
		}
		return nil
	})
	if err != nil {
		t.Error(err)
		return
	}

	// Give it 1 more second to make sure the goroutine is blocked.
	select {
	case <-done:
		t.Fatal("goroutine shouldn't finish")
	case <-time.After(time.Second):
	}

	// New streams should error out with unknown subscriber error.
	stream, err := client.NewStream("test", server.Address().String(), server.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	_, err = stream.Write(make([]byte, 1))
	if err != nil {
		t.Fatal(err)
	}
	_, err = stream.Read(make([]byte, 1))
	if err == nil || !strings.Contains(err.Error(), errUnknownSubscriber.Error()) {
		t.Fatal(err)
	}

	// Close the blocking channel.
	close(block)

	// The goroutine should finish now.
	select {
	case <-time.After(time.Second * 5):
		t.Fatal("goroutine didn't unblock itself")
	case <-done:
	}
}
