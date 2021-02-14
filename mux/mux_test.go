package mux

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uplo-tech/errors"
	"github.com/uplo-tech/fastrand"
	"github.com/uplo-tech/log"
	"github.com/uplo-tech/uplomux/helpers"
	"golang.org/x/net/context"
)

// createTestingMuxs creates a connected pair of type Mux which has already
// completed the encryption handshake and is ready to go.
func createTestingMuxs() (_, _ *Mux) {
	// Prepare tcp connections.
	clientConn, serverConn := createTestingConns()
	clientMux, serverMux, err := createTestingMuxsWithConns(clientConn, serverConn)
	if err != nil {
		panic(err)
	}
	return clientMux, serverMux
}

// createTestingMuxs creates a connected pair of type Mux which has already
// completed the encryption handshake and is ready to go using the provided
// net.Conns.
func createTestingMuxsWithConns(clientConn, serverConn net.Conn) (clientMux, serverMux *Mux, _ error) {
	// Generate server keypair.
	serverPrivKey, serverPubKey := GenerateED25519KeyPair()
	// Get a context.
	ctx := context.Background()

	var wg sync.WaitGroup
	var err1, err2 error
	wg.Add(1)
	go func() {
		defer wg.Done()
		clientMux, err1 = NewClientMux(ctx, clientConn, serverPubKey, log.DiscardLogger, func(*Mux) {}, func(*Mux) {})
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverMux, err2 = NewServerMux(ctx, serverConn, serverPubKey, serverPrivKey, log.DiscardLogger, func(*Mux) {}, func(*Mux) {})
	}()
	wg.Wait()
	return clientMux, serverMux, errors.Compose(err1, err2)
}

// createTestingConns is a helper method to create a pair of connected tcp
// connection ready to use.
func createTestingConns() (clientConn, serverConn net.Conn) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		serverConn, _ = ln.Accept()
		wg.Done()
	}()
	clientConn, _ = net.Dial("tcp", ln.Addr().String())
	wg.Wait()
	return
}

// TestCreateTestingCons tests the createTestingConns helper to make sure the
// connections are open and ready to use.
func TestCreateTestingConns(t *testing.T) {
	// Create some data the client sends the server and vice-versa.
	data := fastrand.Bytes(100)
	clientConn, serverConn := createTestingConns()
	var wg sync.WaitGroup

	// Client
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := clientConn.Write(data)
		if err != nil {
			t.Error(err)
			return
		}
		d := make([]byte, len(data))
		if _, err := io.ReadFull(clientConn, d); err != nil {
			t.Error(err)
			return
		}
		if !bytes.Equal(d, data) {
			t.Error("received data doesn't match data")
			return
		}
	}()
	// Server
	wg.Add(1)
	go func() {
		defer wg.Done()
		d := make([]byte, len(data))
		if _, err := io.ReadFull(serverConn, d); err != nil {
			t.Error(err)
			return
		}
		if !bytes.Equal(d, data) {
			t.Error("received data doesn't match data")
			return
		}
		_, err := serverConn.Write(data)
		if err != nil {
			t.Error(err)
			return
		}
	}()
	// Wait for client and server to be done.
	wg.Wait()
	if err := clientConn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := serverConn.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestCreateTestingMuxs tests if createTestingMuxs produces a couple of
// connected multiplexers.
func TestCreateTestingMuxs(t *testing.T) {
	client, server := createTestingMuxs()
	defer client.Close()
	defer server.Close()
	data := fastrand.Bytes(int(client.settings.MaxFrameSize()) * 5)

	// Check that the version was set correctly.
	if client.staticVersion != Version {
		t.Fatalf("expected version %v but got %v", Version, client.staticVersion)
	}
	if server.staticVersion != Version {
		t.Fatalf("expected version %v but got %v", Version, server.staticVersion)
	}

	var wg sync.WaitGroup
	// Server thread.
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Wait for a stream.
		stream, err := server.AcceptStream()
		if err != nil {
			t.Error(err)
			return
		}
		// Read some data.
		receivedData := make([]byte, len(data))
		if _, err := io.ReadFull(stream, receivedData); err != nil {
			t.Error(err)
			return
		}
		// The data should match.
		if !bytes.Equal(receivedData, data) {
			t.Error("server: received data didn't match")
			return
		}
		// Send the data back.
		written, err := stream.Write(receivedData)
		if err != nil {
			t.Error(err)
			return
		}
		if written < len(receivedData) {
			t.Errorf("server: not enough data written: %v < %v", written, len(receivedData))
			return
		}
		// Close the stream.
		if err := stream.Close(); err != nil {
			t.Error(err)
			return
		}
	}()
	// Client thread.
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Create a new stream.
		stream, err := client.NewStream()
		if err != nil {
			t.Error(err)
			return
		}
		// Write some data.
		written, err := stream.Write(data)
		if err != nil {
			t.Error(err)
			return
		}
		if written != len(data) {
			t.Errorf("client: not enough data written: %v < %v", written, len(data))
			return
		}
		// Read some data.
		receivedData := make([]byte, len(data))
		if _, err := io.ReadFull(stream, receivedData); err != nil {
			t.Error(err)
			return
		}
		// The data should match.
		if !bytes.Equal(receivedData, data) {
			t.Error("client: received data didn't match")
			return
		}
		// Close the stream.
		if err := stream.Close(); err != nil {
			t.Error(err)
			return
		}
	}()
	// Wait for client and server to be done.
	wg.Wait()
}

// TestMuxSendReceiveParallel starts a large number of threads in parallel which
// open streams and send data back and forth.
func TestMuxSendReceiveParallel(t *testing.T) {
	client, server := createTestingMuxs()
	defer client.Close()
	defer server.Close()
	data := fastrand.Bytes(int(client.settings.MaxFrameSize()) * 5)

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
		receivedData := make([]byte, len(data))
		if _, err := io.ReadFull(stream, receivedData); err != nil {
			t.Error(err)
			return
		}
		// The data should match.
		if !bytes.Equal(receivedData, data) {
			t.Error("server: received data didn't match")
			return
		}
		// Send the data back.
		written, err := stream.Write(receivedData)
		if err != nil {
			t.Error(err)
			return
		}
		if written < len(receivedData) {
			t.Errorf("server: not enough data written: %v < %v", written, len(receivedData))
			return
		}
		// Wait a bit before closing the stream to give the peer some time to
		// read the data.
		time.Sleep(time.Second)
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
		written, err := stream.Write(data)
		if err != nil {
			t.Error(err)
			return
		}
		if written < len(data) {
			t.Errorf("client: not enough data written: %v < %v", written, len(data))
			return
		}
		// Read some data.
		receivedData := make([]byte, len(data))
		if _, err := io.ReadFull(stream, receivedData); err != nil {
			t.Error(err)
			return
		}
		// The data should match.
		if !bytes.Equal(receivedData, data) {
			t.Error("client: received data didn't match")
			return
		}
		// Close the stream.
		if err := stream.Close(); err != nil {
			t.Error(err)
			return
		}
	}
	// Spin up the thread pairs.
	var wg sync.WaitGroup
	numThreadPairs := runtime.NumCPU() * 10
	for i := 0; i < numThreadPairs; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			clientWorker()
		}()
		go func() {
			defer wg.Done()
			serverWorker()
		}()
	}
	// Wait for client and server threads to be done.
	close(start)
	wg.Wait()
}

// TestErrorFrame makes sure that reading from a stream that was closed with an
// error frame by the peer will return the correct error.
func TestErrorFrame(t *testing.T) {
	client, server := createTestingMuxs()
	defer client.Close()
	defer server.Close()
	data := fastrand.Bytes(int(client.settings.MaxFrameSize()) * 5)
	expectedErr := errors.New("TestErrorFrame")

	start := make(chan struct{})
	// Server thread.
	halt := make(chan struct{})
	serverWorker := func() {
		<-start
		// Wait for a stream.
		stream, err := server.AcceptStream()
		if err != nil {
			close(halt)
			t.Error(err)
			return
		}
		// Keep reading data. At some point we should get an error since the
		// client sent an error frame.
		receivedData := make([]byte, len(data))
		var readErr error
		err = helpers.Retry(100, 100*time.Millisecond, func() error {
			_, readErr = stream.Read(receivedData)
			if readErr == nil {
				return errors.New("read was successful")
			}
			return nil
		})
		close(halt)
		if err != nil {
			t.Error(readErr)
			return
		}
		// The error we read from the stream should be the error from the error
		// frame.
		if !strings.Contains(readErr.Error(), expectedErr.Error()) {
			t.Errorf("expected error to be %v but was %v", expectedErr, readErr)
			return
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
		// Write half the data.
		_, err = stream.Write(data[:len(data)/2])
		if err != nil {
			t.Error(err)
			return
		}
		// Write an error frame.
		err = client.managedWriteErrorFrame(stream.staticID, errors.New("TestErrorFrame"))
		if err != nil {
			t.Error(err)
			return
		}
		// Wait for the other worker to read the error frame.
		<-halt
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

// TestCloseStream tests that a stream that gets closed correctly causes the
// other end of the pipe to get closed with io.EOF as well instead of blocking
// on Read.
func TestCloseStream(t *testing.T) {
	client, server := createTestingMuxs()
	defer client.Close()
	defer server.Close()
	data := fastrand.Bytes(int(client.settings.MaxFrameSize()) * 5)

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
		// Keep reading data. At some point we should get an error since the
		// client sent an error frame.
		receivedData := make([]byte, len(data))
		var readErr error
		err = helpers.Retry(100, 100*time.Millisecond, func() error {
			_, readErr = stream.Read(receivedData)
			if readErr == nil {
				return errors.New("read was successful")
			}
			return nil
		})
		if err != nil {
			t.Error(readErr)
			return
		}
		// The error we read from the stream should be the error from the error
		// frame.
		if !strings.Contains(readErr.Error(), io.ErrClosedPipe.Error()) {
			t.Errorf("expected error to be %v but was %v", io.ErrClosedPipe, readErr)
			return
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
		// Write half the data.
		_, err = stream.Write(data[:len(data)/2])
		if err != nil {
			t.Error(err)
			return
		}
		// Close the stream.
		if err := stream.Close(); err != nil {
			t.Error(err)
			return
		}
		// Read from it and write to it. Both should return `io.ErrClosedPipe`
		_, err = stream.Write(make([]byte, 1))
		if !errors.Contains(err, io.ErrClosedPipe) {
			t.Error(err)
			return
		}
		_, err = stream.Read(make([]byte, 1))
		if !errors.Contains(err, io.ErrClosedPipe) {
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

// TestMuxHighConcurrency tests writing to and reading from a mux from many
// streams at once.
func TestMuxHighConcurrency(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	client, server := createTestingMuxs()
	defer func() {
		err := client.Close()
		if err != nil {
			t.Fatal(err)
		}
		err = server.Close()
		if err != nil {
			t.Fatal(err)
		}
	}()

	// length of the data being sent over the wire. The first 8 bytes are the
	// number that gets incremented. The remaining data is padding to force the
	// usage of multiple frames.
	dataLen := int(client.settings.MaxFrameSize()) * 5

	// Define the execution time of the test
	executionTime := 10 * time.Second

	// isClosedStream checks for errors related to closed streams. Either by
	// closing a stream yourself or having the peer close it.
	isClosedStream := func(err error) bool {
		return errors.Contains(err, io.ErrClosedPipe)
	}

	// Prepare channels/wgs for controlling the flow of the test.
	var linkWG sync.WaitGroup
	stop := make(chan struct{})
	// isShutdown checks if an error is the result of a shutdown. This means
	// that the stop channel was closed which caused the stream to close and
	// return EOF upon the next read.
	isShutdown := func(err error) bool {
		select {
		case <-stop:
			return errors.Contains(err, io.ErrClosedPipe)
		default:
		}
		return false
	}
	// Server thread.
	serverWorker := func(i int, readDeadline, writeDeadline, peerReadDeadline, peerWriteDeadline time.Time) {
		// Wait for a stream. Interrupt when we hit the peer's write deadline.
		acceptDone := make(chan struct{})
		var stream *Stream
		var err error
		go func() {
			stream, err = server.AcceptStream()
			linkWG.Done()
			close(acceptDone)
		}()
		// Interrupt when peer's deadline is hit before a stream could be
		// created.
		interrupt := time.After(time.Until(peerWriteDeadline))
		select {
		case <-interrupt:
			return
		case <-acceptDone:
		}
		// Check result
		if err != nil {
			t.Error(err)
			return
		}
		// Set deadlines.
		err = stream.SetReadDeadline(readDeadline)
		if err != nil {
			t.Error(err)
			return
		}
		err = stream.SetWriteDeadline(writeDeadline)
		if err != nil {
			t.Error(err)
			return
		}
		// Close the stream.
		defer stream.Close()
		expectedNum := uint64(0)
		buf := make([]byte, dataLen)
		for {
			// Read number.
			_, err := io.ReadFull(stream, buf)
			select {
			case <-stop:
				return
			default:
			}
			if isShutdown(err) {
				return // stream was closed on the other end first
			} else if errors.Contains(err, ErrStreamTimedOut) && time.Now().After(readDeadline) {
				return // stream hit read deadline
			} else if isClosedStream(err) && time.Now().After(readDeadline) {
				return // stream hit read deadline
			} else if isClosedStream(err) && time.Now().After(peerReadDeadline) {
				return // peer stream hit read deadline
			} else if isClosedStream(err) && time.Now().After(peerWriteDeadline) {
				return // peer stream hit write deadline
			} else if err != nil {
				t.Error(err)
				return
			}
			// Compare number to expected number.
			receivedNum := binary.LittleEndian.Uint64(buf)
			if receivedNum != expectedNum {
				t.Error("receivedNum doesn't match expected", receivedNum, expectedNum)
				return
			}
			// Send the next number.
			binary.LittleEndian.PutUint64(buf, receivedNum+1)
			_, err = stream.Write(buf)
			if isShutdown(err) {
				return // stream was closed on the other end first
			} else if errors.Contains(err, ErrStreamTimedOut) && time.Now().After(writeDeadline) {
				return // stream hit write deadline
			} else if isClosedStream(err) && time.Now().After(writeDeadline) {
				return // stream hit write deadline
			} else if isClosedStream(err) && time.Now().After(peerWriteDeadline) {
				return // peer hit write deadline
			} else if isClosedStream(err) && time.Now().After(peerReadDeadline) {
				return // peer hit read deadline
			} else if err != nil {
				t.Error(err)
				return
			}
			// The next number we expect is two greater than before.
			expectedNum += 2
			// Check for stop condition.
			select {
			case <-stop:
				return
			default:
			}
		}
	}
	// Client thread.
	clientWorker := func(i int, readDeadline, writeDeadline, peerReadDeadline, peerWriteDeadline time.Time) {
		// Create a new stream.
		stream, err := client.NewStream()
		if err != nil {
			t.Error(err)
			return
		}
		// Close the stream.
		defer stream.Close()
		// Set deadlines.
		err = stream.SetReadDeadline(readDeadline)
		if err != nil {
			t.Error(err)
			return
		}
		err = stream.SetWriteDeadline(writeDeadline)
		if err != nil {
			t.Error(err)
			return
		}
		expectedNum := uint64(1)
		buf := make([]byte, dataLen)
		for {
			// The number we send is expectedNum-1 since the other peer will
			// increment it.
			binary.LittleEndian.PutUint64(buf, expectedNum-1)
			_, err := stream.Write(buf)
			if errors.Contains(err, ErrStreamTimedOut) && time.Now().After(writeDeadline) {
				return // stream hit write deadline
			} else if isClosedStream(err) && time.Now().After(peerWriteDeadline) {
				return // peer hit write deadline
			} else if isClosedStream(err) && time.Now().After(peerReadDeadline) {
				return // peer hit read deadline
			} else if err != nil {
				t.Error(err)
				return
			}
			// Read number.
			_, err = io.ReadFull(stream, buf)
			if isShutdown(err) {
				return // stream was closed on the other end first
			} else if errors.Contains(err, ErrStreamTimedOut) && time.Now().After(readDeadline) {
				return // stream hit read deadline
			} else if isClosedStream(err) && time.Now().After(peerReadDeadline) {
				return // peer stream hit read deadline
			} else if isClosedStream(err) && time.Now().After(peerWriteDeadline) {
				return // peer stream hit write deadline
			} else if err != nil {
				t.Error(err)
				return
			}
			// Compare number to expected number.
			receivedNum := binary.LittleEndian.Uint64(buf)
			if receivedNum != expectedNum {
				t.Error("receivedNum doesn't match expected", receivedNum, expectedNum)
				return
			}
			// Increment the expected number.
			expectedNum += 2
			// Check for stop condition.
			select {
			case <-stop:
				return
			default:
			}
		}
	}
	// Declare a helper method which returns a random read deadline and write
	// deadline plus bools indicating whether the corresponding deadline will be
	// hit during the execution of the test.
	deadlines := func() (rd, wd time.Time) {
		now := time.Now()
		rd = now.Add(time.Hour)
		wd = now.Add(time.Hour)
		// 10% chance for the stream to hit a read deadline
		if fastrand.Intn(100) < 10 {
			d := time.Duration(fastrand.Intn(int(executionTime.Seconds()))+1) * time.Second
			rd = now.Add(d)
		}
		// 10% chance for the stream to hit a write deadline
		if fastrand.Intn(100) < 10 {
			d := time.Duration(fastrand.Intn(int(executionTime.Seconds()))+1) * time.Second
			wd = now.Add(d)
		}
		return
	}
	// Spin up the threads in pairs.
	var wg sync.WaitGroup
	numThreadPairs := runtime.NumCPU() * 10
	for i := 0; i < numThreadPairs; i++ {
		clientRD, clientWD := deadlines()
		serverRD, serverWD := deadlines()
		wg.Add(2)
		linkWG.Add(1)
		go func(i int) {
			defer wg.Done()
			clientWorker(i, clientRD, clientWD, serverRD, serverWD)
		}(i)
		go func(i int) {
			defer wg.Done()
			serverWorker(i, serverRD, serverWD, clientRD, clientWD)
		}(i)
		linkWG.Wait()
	}
	// Wait for client and server threads to be done.
	time.Sleep(executionTime)
	close(stop)
	wg.Wait()
}

// TestMuxReadPartialFrame tests that reading a frame partially with multiple
// calls to Read also works.
func TestMuxReadPartialFrame(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	client, server := createTestingMuxs()
	defer client.Close()
	defer server.Close()
	data := fastrand.Bytes(int(client.settings.MaxFrameSize() * 5))

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
		// Read some data byte by byte.
		b := make([]byte, 1)
		var combined []byte
		for i := 0; i < len(data); i++ {
			if i == 0 {
				// Force that the peer closes the stream. We still want to be
				// able to read the partial frame without an error.
				time.Sleep(time.Second)
			}
			if _, err := io.ReadFull(stream, b); err != nil {
				t.Error(err)
				return
			}
			combined = append(combined, b...)
		}
		// The data should match.
		if !bytes.Equal(combined, data) {
			t.Error("server: received data didn't match")
			return
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
		written, err := stream.Write(data)
		if err != nil {
			t.Error(err)
			return
		}
		if written < len(data) {
			t.Errorf("client: not enough data written: %v < %v", written, len(data))
			return
		}
		// Close the stream.
		if err := stream.Close(); err != nil {
			t.Error(err)
			return
		}
	}
	// Spin up the thread pairs.
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

// TestNewFrameID is a unit test for "newFrameID".
func TestNewFrameID(t *testing.T) {
	client, server := createTestingMuxs()
	defer client.Close()
	defer server.Close()

	// Make sure both client and server start with the right ids.
	clientID := client.newFrameID()
	serverID := server.newFrameID()

	// The first value is checked against a hardcoded value which equals
	// numReservedFrameIDs to make sure changing the constant doesn't go
	// unnoticed.
	if clientID != 256 {
		t.Fatal("clientID", clientID, 256)
	}
	if serverID != clientID+1 {
		t.Fatal("serverID", clientID, clientID+1)
	}

	// Try it a few more times in a loop.
	for i := uint32(0); i < 100; i++ {
		if clientID != numReservedFrameIDs+2*i {
			t.Fatal("clientID", clientID, numReservedFrameIDs+2*i)
		}
		if serverID != clientID+1 {
			t.Fatal("serverID", clientID, clientID+1)
		}
		clientID = client.newFrameID()
		serverID = server.newFrameID()
	}

	// Test that overflows are handled correctly.
	client.nextFrameID = uint32(0)
	server.nextFrameID = uint32(1)
	client.nextFrameID -= 2
	server.nextFrameID -= 2

	clientID = client.newFrameID()
	serverID = server.newFrameID()
	if clientID != math.MaxUint32-1 {
		t.Fatal("clientID", clientID, math.MaxUint32-1)
	}
	if serverID != clientID+1 {
		t.Fatal("serverID", clientID, clientID+1)
	}

	clientID = client.newFrameID()
	serverID = server.newFrameID()
	if clientID != 256 {
		t.Fatal("clientID", clientID, 256)
	}
	if serverID != clientID+1 {
		t.Fatal("serverID", clientID, clientID+1)
	}

	loopTest := func(start, end uint32, closeStreams bool) {
		client.nextFrameID = 256
		server.nextFrameID = client.nextFrameID + 1
		for i := start; i < end; i++ {
			clientStream, err := client.NewStream()
			if err != nil {
				t.Fatal(err)
			}
			serverStream, err := server.NewStream()
			if err != nil {
				t.Fatal(err)
			}
			if closeStreams {
				defer clientStream.Close()
				defer serverStream.Close()
			}

			clientID = clientStream.staticID
			serverID = serverStream.staticID
			if clientID != numReservedFrameIDs+2*i {
				t.Fatal("clientID", clientID, numReservedFrameIDs+2*i)
			}
			if serverID != clientID+1 {
				t.Fatal("serverID", clientID, clientID+1)
			}
		}
	}

	// Try a few more times. This time by calling NewStream. This confirms that
	// NewStream is calling newFrameID.
	loopTest(0, 100, false)

	// Reset frame ids again and try again. This makes sure we don't reuse taken
	// ids from open streams.
	loopTest(100, 200, true)

	// One more time but this time confirm that we also don't reuse closed
	// stream ids.
	loopTest(200, 300, true)
}
