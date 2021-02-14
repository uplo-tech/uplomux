package mux

import (
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uplo-tech/errors"
	"github.com/uplo-tech/fastrand"
)

// unstableConn implements an unstablet net.Conn which will randomly drop
// connections.
type unstableConn struct {
	staticFailureProb float64

	staticR      io.ReadCloser
	readDeadline time.Time
	rmu          sync.Mutex

	staticW       io.WriteCloser
	writeDeadline time.Time
	wmu           sync.Mutex
}

// Close closes the underlying reader and writer.
func (conn *unstableConn) Close() error {
	return errors.Compose(conn.staticR.Close(), conn.staticW.Close())
}

// LocalAddr returns a hardcoded address.
func (conn *unstableConn) LocalAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 1234,
	}
}

// RemoteAddr returns a hardcoded address.
func (conn *unstableConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 4321,
	}
}

// Read implements io.Reader by forwarding the read to the underlying reader.
func (conn *unstableConn) Read(b []byte) (n int, err error) {
	conn.rmu.Lock()
	defer conn.rmu.Unlock()

	if conn.staticShouldFail() {
		return 0, errors.New("Read: random jitter")
	}

	timer := time.NewTimer(time.Until(conn.readDeadline))
	done := make(chan struct{})
	go func() {
		n, err = conn.staticR.Read(b)
		close(done)
	}()
	select {
	case <-timer.C:
		return 0, errors.New(("Read: timeout"))
	case <-done:
	}
	if !timer.Stop() {
		<-timer.C // drain the timer
	}
	return
}

// Write implements io.Reader by forwarding the write to the underlying writer.
func (conn *unstableConn) Write(b []byte) (n int, err error) {
	conn.wmu.Lock()
	defer conn.wmu.Unlock()

	if conn.staticShouldFail() {
		return 0, errors.New("Write: random jitter")
	}

	timer := time.NewTimer(time.Until(conn.writeDeadline))
	done := make(chan struct{})
	go func() {
		n, err = conn.staticW.Write(b)
		close(done)
	}()
	select {
	case <-timer.C:
		return 0, errors.New(("Write: timeout"))
	case <-done:
	}
	if !timer.Stop() {
		<-timer.C // drain the timer
	}
	return
}

// SetDeadline behaves the same as setting the read and write deadlines
// together.
func (conn *unstableConn) SetDeadline(t time.Time) error {
	err1 := conn.SetReadDeadline(t)
	err2 := conn.SetWriteDeadline(t)
	return errors.Compose(err1, err2)
}

// SetReadDeadline is a no-op.
func (conn *unstableConn) SetReadDeadline(t time.Time) error {
	conn.rmu.Lock()
	defer conn.rmu.Unlock()
	conn.readDeadline = t
	return nil
}

// SetWriteDeadline is a no-op.
func (conn *unstableConn) SetWriteDeadline(t time.Time) error {
	conn.wmu.Lock()
	defer conn.wmu.Unlock()
	conn.writeDeadline = t
	return nil
}

// staticShouldFail throws a dice and returns true if the following action
// should fail.
func (conn *unstableConn) staticShouldFail() bool {
	return fastrand.Intn(100) < int(conn.staticFailureProb*100)
}

// newUnstableConns will create a pair of linked unstableConns.
func newUnstableConns(failureProb float64) (client, server net.Conn) {
	if failureProb < 0 || failureProb > 1 {
		panic("invalid failure probability")
	}

	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()

	client = &unstableConn{
		staticR:           r1,
		staticW:           w2,
		staticFailureProb: failureProb,
	}
	server = &unstableConn{
		staticW:           w1,
		staticR:           r2,
		staticFailureProb: failureProb,
	}
	return
}

// TestNewMuxUnstableConns tests creating many muxs using an unstable
// connection.
func TestNewMuxUnstableConns(t *testing.T) {
	// Test vars.
	numRuns := 10000
	numThreads := runtime.NumCPU()

	// Declare the runner.
	atomicRunsRemaining := int64(numRuns)
	run := func() {
		for {
			i := atomic.AddInt64(&atomicRunsRemaining, -1)
			if i < 0 {
				return // done
			}

			// Create unstable connections.
			clientConn, serverConn := newUnstableConns(0.05) // 5%

			// Wrap them.
			client, server, err := createTestingMuxsWithConns(clientConn, serverConn)
			if err != nil {
				// This is fine. No need to check errors. Just close the
				// connections since we can't assume the muxs took ownership
				// over them.
				_ = clientConn.Close()
				_ = serverConn.Close()
				continue
			}

			// Close them again.
			err1 := client.Close()
			err2 := server.Close()
			if err := errors.Compose(err1, err2); err != nil {
				t.Error(err)
				return
			}
		}
	}

	// Spawn the workers.
	var wg sync.WaitGroup
	for i := 0; i < numThreads; i++ {
		wg.Add(1)
		go func() {
			run()
			wg.Done()
		}()
	}
	// Wait for the work to be done.
	wg.Wait()
}
