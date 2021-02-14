package mux

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uplo-tech/errors"
	"github.com/uplo-tech/fastrand"
	"github.com/uplo-tech/uplomux/deps"
	"github.com/uplo-tech/uplomux/helpers"
)

type (
	// dependencyDelayWrite adds a delay when calling Disrupt with the correct
	// string. The delay happens in managedWrite after initializing the
	// goroutine that enforces the write timeout but before starting the first
	// write to the underlying connection.
	dependencyDelayWrite struct {
		deps.ProductionDependencies
		delay time.Duration
	}
)

// newDependencyDelayWrite creates a new dependencyDelayWrite dependency from
// the specified delay.
func newDependencyDelayWrite(delay time.Duration) deps.Dependencies {
	return &dependencyDelayWrite{
		delay: delay,
	}
}

// Disrupt can be used to inject specific behavior into a module by overwriting
// it using a custom dependency
func (ddw *dependencyDelayWrite) Disrupt(s string) bool {
	if s == "delayWrite" {
		time.Sleep(ddw.delay)
		return true
	}
	return false
}

// TestMaxTimeout tests that if a MaxTimeout is reached, a mux will be closed
// and its peer will realize that the connection has been closed and close
// itself. Both should call the closeCallback function.
func TestMaxTimeout(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	peer1, peer2 := createTestingMuxs()

	// Replace the closeCallbacks on both peers.
	var numCallbacks1, numCallbacks2 int
	peer1.staticCloseCallback = func(*Mux) {
		numCallbacks1++
	}
	peer2.staticCloseCallback = func(*Mux) {
		numCallbacks2++
	}

	// Change the maxTimeout on peer1.
	peer1.staticMu.Lock()
	peer1.settings.MaxTimeout = 1
	err := peer1.updateDeadline()
	if err != nil {
		t.Fatal(err)
	}
	peer1.staticMu.Unlock()

	// Wait for 1 second and make sure peer1 timed out.
	err = helpers.Retry(10, time.Second, func() error {
		select {
		case <-peer1.staticCtx.Done():
			return nil
		default:
		}
		return errors.New("peer1 hasn't timed out yet")
	})
	if err != nil {
		t.Fatal(err)
	}

	// The other peer should realize the connection is closed and close itself.
	err = helpers.Retry(10, time.Second, func() error {
		select {
		case <-peer2.staticCtx.Done():
			return nil
		default:
		}
		return errors.New("peer2 hasn't closed itself yet")
	})
	if err != nil {
		t.Fatal(err)
	}

	// Close both peers to make sure deferred calls to Close don't panic in
	// production code.
	err1 := peer1.Close()
	err2 := peer2.Close()
	if err := errors.Compose(err1, err2); err != nil {
		t.Fatal(err)
	}

	// Check that both callbacks have been called exactly once.
	if numCallbacks1 != 1 {
		t.Fatalf("expected callback to be called %v but was %v", 1, numCallbacks1)
	}
	if numCallbacks2 != 1 {
		t.Fatalf("expected callback to be called %v but was %v", 1, numCallbacks2)
	}
}

// TestMaxTimeoutKeepAliveWriteRead makes sure that writing to a stream and
// reading from it will keep a connection from timing out.
func TestMaxTimeoutKeepAliveWriteRead(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	peer1, peer2 := createTestingMuxs()

	// Replace the closeCallbacks on both peers.
	peer1.staticCloseCallback = func(*Mux) {
		t.Error("callback1 called")
	}
	peer2.staticCloseCallback = func(*Mux) {
		t.Error("callback2 called")
	}

	// Continuously send on one peer and read on the other to avoid neither of them
	// timing out.
	cancel := make(chan struct{})
	go func() {
		stream, err := peer1.AcceptStream()
		if err != nil {
			t.Error(err)
			return
		}
		data := make([]byte, 100)
		for {
			select {
			case <-cancel:
				return
			default:
			}
			err := stream.SetReadDeadline(time.Now().Add(time.Second))
			if err != nil {
				t.Error(err)
				return
			}
			_, err = stream.Read(data)
			if err != nil {
				t.Error(err)
				return
			}
		}
	}()
	go func() {
		stream, err := peer2.NewStream()
		if err != nil {
			t.Error(err)
		}
		for {
			select {
			case <-cancel:
				return
			default:
			}
			err := stream.SetWriteDeadline(time.Now().Add(time.Second))
			if err != nil {
				t.Error(err)
				return
			}
			_, err = stream.Write(fastrand.Bytes(100))
			if err != nil {
				t.Error(err)
				return
			}
		}
	}()

	// Change the maxTimeout on both peers. Then notify the mux using the
	// channel.
	maxTimeout := uint16(2)
	peer1.staticMu.Lock()
	peer1.settings.MaxTimeout = maxTimeout
	err := peer1.updateDeadline()
	if err != nil {
		t.Fatal(err)
	}
	peer1.staticMu.Unlock()
	peer2.staticMu.Lock()
	peer2.settings.MaxTimeout = maxTimeout
	err = peer2.updateDeadline()
	if err != nil {
		t.Fatal(err)
	}
	peer2.staticMu.Unlock()

	// Sleep 5 times longer than the timeout to make sure we keep sending and
	// receiving data successfully.
	time.Sleep(time.Second * time.Duration(maxTimeout) * 5)

	// NOTE: Close is not called in this test to avoid hitting the callbacks and
	// causing the test to fail.
}

// TestStreamSetDeadline tests that if a deadline is reached, a stream will
// return ErrStreamTimedOut on Writes and Reads.
func TestStreamSetDeadline(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	peer1, peer2 := createTestingMuxs()

	dataLen := 10
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Accept a stream.
		stream, err := peer2.AcceptStream()
		if err != nil {
			t.Error(err)
			return
		}
		// Set the deadline to 1 second.
		err = stream.SetReadDeadline(time.Now().Add(time.Second))
		if err != nil {
			t.Error(err)
			return
		}
		// Wait for 2 seconds before reading from the stream. It should time
		// out.
		time.Sleep(time.Second * 2)
		// Read should fail due to timed out streamm.
		data := make([]byte, dataLen)
		n, err := stream.Read(data)
		if !errors.Contains(err, ErrStreamTimedOut) {
			t.Error("Expected ErrStreamTimedOut got", err, n)
			return
		}
		// Start a new stream and force the write to timeout using a dependency.
		peer2.staticDeps = newDependencyDelayWrite(time.Second * 2)
		stream, err = peer2.NewStream()
		if err != nil {
			t.Error(err)
			return
		}
		err = stream.SetWriteDeadline(time.Now().Add(time.Second))
		if err != nil {
			t.Error(err)
			return
		}
		_, err = stream.Write(fastrand.Bytes(dataLen))
		if !errors.Contains(err, ErrStreamTimedOut) {
			t.Error(err)
			return
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Create a stream.
		stream, err := peer1.NewStream()
		if err != nil {
			t.Error(err)
			return
		}
		// Write to the stream to get it established.
		_, err = stream.Write(fastrand.Bytes(dataLen))
		if err != nil {
			t.Error(err)
			return
		}
	}()
	// Wait for threads to finish
	wg.Wait()
}

// TestMaxTimeoutKeepAliveFrame makes sure that sending keepalive frames will
// keep a connection from timing out.
func TestMaxTimeoutKeepAliveFrame(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	peer1, peer2 := createTestingMuxs()

	// Replace the closeCallbacks on both peers.
	peer1.staticCloseCallback = func(*Mux) {
		t.Error("callback1 called")
	}
	peer2.staticCloseCallback = func(*Mux) {
		t.Error("callback2 called")
	}

	// Continuously send on one peer and read on the other to avoid neither of them
	// timing out.
	cancel := make(chan struct{})
	go func() {
		for {
			select {
			case <-cancel:
				return
			default:
			}
			if err := peer1.Keepalive(); err != nil {
				t.Error(err)
				return
			}
		}
	}()

	// Change the maxTimeout on both peers. Then notify the mux using the
	// channel.
	maxTimeout := uint16(1)
	peer1.staticMu.Lock()
	peer1.settings.MaxTimeout = maxTimeout
	err := peer1.updateDeadline()
	if err != nil {
		t.Fatal(err)
	}
	peer1.staticMu.Unlock()
	peer2.staticMu.Lock()
	peer2.settings.MaxTimeout = maxTimeout
	err = peer2.updateDeadline()
	if err != nil {
		t.Fatal(err)
	}
	peer2.staticMu.Unlock()

	// Sleep 5 times longer than the timeout to make sure we keep sending and
	// receiving data successfully.
	time.Sleep(time.Second * time.Duration(maxTimeout) * 5)

	// NOTE: Close is not called in this test to avoid hitting the callbacks and
	// causing the test to fail.
}

// TestTimeoutCallback makes sure the timeout callback methods are triggered
// correctly.
func TestTimeoutCallback(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	peer1, peer2 := createTestingMuxs()

	// Replace the closeCallbacks on both peers.
	numPeer1Callbacks := uint64(0)
	numPeer2Callbacks := uint64(0)
	peer1.staticTimeoutCallback = func(mux *Mux) {
		// Send a keepalive the first time we receive a callback.
		if atomic.LoadUint64(&numPeer1Callbacks) == 0 {
			if err := mux.Keepalive(); err != nil {
				t.Fatal(err)
			}
		}
		atomic.AddUint64(&numPeer1Callbacks, 1)
	}
	peer2.staticTimeoutCallback = func(*Mux) {
		atomic.AddUint64(&numPeer2Callbacks, 1)
	}

	// Change the maxTimeout on both peers. Then notify the mux using the
	// channel. This should cause the timeout callbacks to be called.
	maxTimeout := uint16(5)
	peer1.staticMu.Lock()
	peer1.settings.MaxTimeout = maxTimeout
	err := peer1.updateDeadline()
	if err != nil {
		t.Fatal(err)
	}
	peer1.staticMu.Unlock()
	peer2.staticMu.Lock()
	peer2.settings.MaxTimeout = maxTimeout
	err = peer2.updateDeadline()
	if err != nil {
		t.Fatal(err)
	}
	peer2.staticMu.Unlock()

	// The callbacks should've been called 2 times each.
	err = helpers.Retry(100, 100*time.Millisecond, func() error {
		if n := atomic.LoadUint64(&numPeer1Callbacks); n != 2 {
			return fmt.Errorf("expected %v peer1 callbacks but got %v", 2, n)
		}
		if n := atomic.LoadUint64(&numPeer2Callbacks); n != 2 {
			return fmt.Errorf("expected %v peer2 callbacks but got %v", 2, n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestKeepaliveCallbackDeadlock makes sure that it's possible to close a mux
// within the keepalive callback without a deadlock.
func TestKeepaliveCallbackDeadlock(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	peer1, peer2 := createTestingMuxs()

	// Change the timeout callback to 1 second and have the callback close the
	// muxs.
	var wg sync.WaitGroup
	wg.Add(1)
	peer1.staticMu.Lock()
	peer1.staticTimeoutCallback = func(m *Mux) {
		defer wg.Done()
		err := errors.Compose(peer1.Close(), peer2.Close())
		if err != nil {
			t.Fatal(err)
		}
	}
	peer1.timeoutCallbackTime = time.Now().Add(time.Second)
	peer1.staticMu.Unlock()

	peer1.staticTimeoutChanged <- struct{}{}
	wg.Wait()
}
