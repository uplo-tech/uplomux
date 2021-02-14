package mux

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/uplo-tech/errors"
	"github.com/uplo-tech/fastrand"
)

// wsTester is a helper type with an http.Server that has a single route
// registered for testing websockets.
type wsTester struct {
	wg     sync.WaitGroup
	server *http.Server
	url    string
}

// NewClient connects a new peer to the websocket server.
func (wst *wsTester) NewClient() (*WSConn, error) {
	clientConn, _, err := websocket.DefaultDialer.Dial(wst.url, nil)
	if err != nil {
		return nil, err
	}
	return newWSConn(clientConn), nil
}

// Close closes the tester's underlying resources.
func (wst *wsTester) Close() error {
	err1 := wst.server.Shutdown(context.Background())
	wst.wg.Wait()
	return errors.Compose(err1)
}

// newWSTester creates a new tester which includes a http server with a single
// websocket endpoint. The provided method will be used to handle incoming
// WSConns.
func newWSTester(serverHandle func(*WSConn)) *wsTester {
	// Define a handler to upgrade the connection to a websocket.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		upgrader := websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		}
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			return
		}
		serverHandle(newWSConn(conn))
	})
	// Get a listener.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	// Declare a server and run it.
	server := &http.Server{
		Addr:    l.Addr().String(),
		Handler: mux,
	}
	// Create the tester.
	tester := &wsTester{
		server: server,
		url:    fmt.Sprintf("ws://%v", l.Addr().String()),
	}
	tester.wg.Add(1)
	go func() {
		defer tester.wg.Done()
		_ = server.Serve(l)
	}()
	return tester
}

// TestCreateWebSocketPair creates a WSTester and makes sure that connecting a
// new client triggers the server's endpoint.
func TestCreateWebSocketPair(t *testing.T) {
	var atomicCalls uint64
	serverFunc := func(conn *WSConn) {
		atomic.AddUint64(&atomicCalls, 1)
	}
	// Start the server.
	wst := newWSTester(serverFunc)

	// Connect a client.
	_, err := wst.NewClient()
	if err != nil {
		t.Fatal(err)
	}

	// Close the server.
	if err := wst.Close(); err != nil {
		t.Fatal(err)
	}

	// Check the number of times the server handler has been called.
	numCalls := atomic.LoadUint64(&atomicCalls)
	if numCalls != 1 {
		t.Fatal("expected handler to be called once but was", numCalls)
	}
}

// testReadWithCustomServer is a subtest that will test various ways of reading
// from a connection to a websocket server. The server is assumed to always
// return `testData`.
func testReadWithCustomServer(t *testing.T, testData []byte, serverFunc func(conn *WSConn)) {
	// Start the server.
	wst := newWSTester(serverFunc)
	defer wst.Close()

	// Connect a client that reads all of the data at once.
	client, err := wst.NewClient()
	if err != nil {
		t.Fatal(err)
	}
	readBuf := make([]byte, len(testData))
	_, err = io.ReadFull(client, readBuf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readBuf, testData) {
		t.Fatal("readBuf doesn't match testData")
	}

	// Connect a client that reads 2 times 50% of the data.
	client, err = wst.NewClient()
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadFull(client, readBuf[:len(readBuf)/2])
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadFull(client, readBuf[len(readBuf)/2:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readBuf, testData) {
		t.Fatal("readBuf doesn't match testData")
	}

	// Connect a client that reads more than the available data.
	client, err = wst.NewClient()
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadFull(client, readBuf)
	if err != nil {
		t.Fatal(err)
	}
	n, err := client.Read(readBuf)
	if n != 0 || err != nil {
		t.Fatal("expecte n == 0 and err == nil", n, err)
	}

	// Connect a client that reads only half the data without closing the conn.
	// This shouldn't block the next client.
	client, err = wst.NewClient()
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadFull(client, readBuf[:len(readBuf)/2])
	if err != nil {
		t.Fatal(err)
	}

	// Connect a client that does random reading until all of the data is read.
	client, err = wst.NewClient()
	if err != nil {
		t.Fatal(err)
	}
	var readBytes int
	for remainingBytes := len(testData) - readBytes; remainingBytes > 0; remainingBytes = len(testData) - readBytes {
		toRead := fastrand.Intn(remainingBytes) + 1
		_, err = io.ReadFull(client, readBuf[readBytes:][:toRead])
		if err != nil {
			t.Fatal(err)
		}
		readBytes += toRead
	}
	if !bytes.Equal(readBuf, testData) {
		t.Fatal("readBuf doesn't match testData")
	}
}

// TestWSConnReadWrite is a group of tests that tests reading and writing
// from/to WSConns.
func TestWSConnReadWrite(t *testing.T) {
	// Random data for all subtests.
	testData := fastrand.Bytes(100)

	// Subtest1: Server returns the testData with a single Write.
	server1 := func(conn *WSConn) {
		n, err := conn.Write(testData)
		if err != nil {
			t.Error(err)
			return
		}
		if len(testData) != n {
			t.Errorf("expected %v bytes to be written but was %v", len(testData), n)
			return
		}
	}

	// Subtest2: Server returns the testData with two Writes.
	server2 := func(conn *WSConn) {
		n1, err := conn.Write(testData[:len(testData)/2])
		if err != nil {
			t.Error(err)
			return
		}
		n2, err := conn.Write(testData[len(testData)/2:])
		if err != nil {
			t.Error(err)
			return
		}
		n := n1 + n2
		if len(testData) != n {
			t.Errorf("expected %v bytes to be written but was %v", len(testData), n)
			return
		}
	}

	// Subtest3: Server returns the testData with random Writes.
	server3 := func(conn *WSConn) {
		var written int
		for remainingBytes := len(testData) - written; remainingBytes > 0; remainingBytes = len(testData) - written {
			toWrite := fastrand.Intn(remainingBytes) + 1
			n, err := conn.Write(testData[written:][:toWrite])
			if err != nil {
				t.Fatal(err)
			}
			if n != toWrite {
				t.Errorf("expected %v bytes to be written but was %v", toWrite, n)
				return
			}
			written += toWrite
		}
	}

	// Execute tests.
	t.Run("ServerSingleWrite", func(t *testing.T) {
		testReadWithCustomServer(t, testData, server1)
	})
	t.Run("ServerDoubleWrite", func(t *testing.T) {
		testReadWithCustomServer(t, testData, server2)
	})
	t.Run("ServerRandomWrite", func(t *testing.T) {
		testReadWithCustomServer(t, testData, server3)
	})
}

// TestWSConnDeadline tests that setting the deadlines works as expected.
func TestWSConnDeadline(t *testing.T) {
	// Defines a server which just reads some data and if successful writes the
	// data back. This way the clients won't get blocked.
	data := fastrand.Bytes(10)
	serverFunc := func(conn *WSConn) {
		// Read some data.
		b := make([]byte, len(data))
		_, err := io.ReadFull(conn, b)
		if err != nil {
			return
		}
		// Write data back.
		_, _ = conn.Write(b)
		return
	}

	// Start the server.
	wst := newWSTester(serverFunc)
	defer wst.Close()

	// Declare helper for determining deadline error.
	isErrDeadline := func(err error) bool {
		if err == nil {
			return false
		}
		return strings.Contains(err.Error(), "i/o timeout")
	}

	// Declare helper.
	checkDeadline := func(wst *wsTester, writeDeadline, readDeadline func(*WSConn), readFail, writeFail bool) {
		// Get client.
		client, err := wst.NewClient()
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		// Set pre-write deadline.
		writeDeadline(client)
		time.Sleep(100 * time.Millisecond)
		// Write some data. This should fail if "writeFail" is specified.
		_, err = client.Write(data)
		if err != nil && !writeFail {
			t.Fatal(err)
		} else if writeFail && !isErrDeadline(err) {
			t.Fatal("expected write to fail", err)
		}
		// If writing was expected to fail we abort since we won't receive a
		// response from the server.
		if writeFail {
			return
		}
		// Set post-write deadline.
		readDeadline(client)
		time.Sleep(100 * time.Millisecond)
		// Try reading. This should fail if "readFail" is specified.
		_, err = io.ReadFull(client, make([]byte, len(data)))
		if err != nil && !readFail {
			t.Fatal(err)
		} else if readFail && !isErrDeadline(err) {
			t.Fatal("expected read to fail", err)
		}
	}

	// Execute tests.
	deadline := time.Now()

	// No deadline
	noDeadline := func(client *WSConn) {
		if err := client.SetDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
	checkDeadline(wst, noDeadline, noDeadline, false, false)

	// ReadDeadline
	checkDeadline(wst, noDeadline, func(client *WSConn) {
		if err := client.SetReadDeadline(deadline); err != nil {
			t.Fatal(err)
		}
	}, true, false)

	// WriteDeadline
	checkDeadline(wst, func(client *WSConn) {
		if err := client.SetWriteDeadline(deadline); err != nil {
			t.Fatal(err)
		}
	}, noDeadline, false, true)

	// Same again but with SetDeadline.
	checkDeadline(wst, noDeadline, func(client *WSConn) {
		if err := client.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
	}, true, false)

	checkDeadline(wst, func(client *WSConn) {
		if err := client.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
	}, noDeadline, false, true)
}
