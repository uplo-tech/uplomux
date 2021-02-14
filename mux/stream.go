package mux

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/uplo-tech/errors"
)

// ErrStreamTimedOut is returned when trying to read from or write to a timed
// out stream.
var ErrStreamTimedOut = errors.New("stream timed out")

// Stream implements a multiplexed connection to the connected peer. A Stream is
// a drop-in replacement for a net.Conn.
type Stream struct {
	readDeadline  time.Time // timeout for reading from stream
	writeDeadline time.Time // deadline for writing to stream
	mu            sync.Mutex

	staticPayloadChan chan []byte // the reader thread sends the data it reads from the stream on this channel
	partialFrame      []byte

	bandwidthLimit BandwidthLimit

	staticCtxCancel context.CancelFunc
	staticCtx       context.Context

	lazyBuf []byte

	closedErr error
	staticID  uint32
	staticMux *Mux
}

// managedNewStream creates a new Stream object.
func (m *Mux) newStream(ctx context.Context, id uint32) *Stream {
	// Prepare a slice for the buffer and append the initial payload right away.
	ctx, cancel := context.WithCancel(ctx)
	stream := &Stream{
		bandwidthLimit:    &NoLimit{},  // no limit
		readDeadline:      time.Time{}, // infinite
		writeDeadline:     time.Time{}, // infinite
		staticPayloadChan: make(chan []byte),
		staticID:          id,
		staticMux:         m,
		staticCtx:         ctx,
		staticCtxCancel:   cancel,
	}
	m.streams[stream.staticID] = stream
	return stream
}

// NewStream creates a new outgoing stream.
func (m *Mux) NewStream() (*Stream, error) {
	m.staticMu.Lock()
	defer m.staticMu.Unlock()
	stream := m.newStream(m.staticCtx, m.newFrameID())
	return stream, nil
}

// AcceptStream listens for a new incoming stream.
func (m *Mux) AcceptStream() (*Stream, error) {
	return m.managedAcceptStream()
}

// Close implements net.Conn. It removes the stream from the mux and closes the
// underlying writer and reader.
func (s *Stream) Close() error {
	_, err := s.staticMux.managedRemoveStream(s.staticID, nil)
	if err != nil {
		return errors.AddContext(err, "failed to remove stream from mux when closing stream")
	}
	// Send the final frame. This might block on a bad connection. That's why we
	// do it in a separate goroutine. It's also not important for us to know
	// whether it succeeded since it's more of a courtesy.
	go func() {
		_ = s.staticMux.managedWriteFinalFrame(s.staticID)
	}()
	return nil
}

// Limit gets the limit on the stream.
func (s *Stream) Limit() BandwidthLimit {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bandwidthLimit
}

// Mux returns the stream's underlying mux.
func (s *Stream) Mux() *Mux {
	return s.staticMux
}

// managedClose is similar to close but doesn't remove the stream from its
// parent mux. Therefore Close should usually be called.
func (s *Stream) managedClose(err error) error {
	s.mu.Lock()
	if err == nil {
		err = io.ErrClosedPipe
	}
	s.closedErr = err
	s.mu.Unlock()
	s.staticCtxCancel()
	return nil
}

// managedRecordDownload calls RecordDownload on the underlying limit.
func (s *Stream) managedRecordDownload(bytes uint64) error {
	s.mu.Lock()
	limit := s.bandwidthLimit
	s.mu.Unlock()
	return limit.RecordDownload(bytes)
}

// managedRecordUpload calls RecordUpload on the underlying limit.
func (s *Stream) managedRecordUpload(bytes uint64) error {
	s.mu.Lock()
	limit := s.bandwidthLimit
	s.mu.Unlock()
	return limit.RecordUpload(bytes)
}

// LazyWrite adds some data to the streams internal buffer to be written the
// next time s.Write is called.
func (s *Stream) LazyWrite(d []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lazyBuf = append(s.lazyBuf, d...)
}

// LocalAddr implements net.Conn.
func (s *Stream) LocalAddr() net.Addr {
	return s.staticMux.staticConn.LocalAddr()
}

// Read implements net.Conn by reading from a reader which is fed by the data
// fetching background thread of the mux. If no data is available Read will
// block. If data is available and not read, other streams of the same
// connection will be blocked as well.
func (s *Stream) Read(b []byte) (n int, err error) {
	// Check deadline before reading.
	deadline := s.managedReadDeadline()
	if !deadline.IsZero() && time.Now().After(deadline) {
		return 0, ErrStreamTimedOut
	}
	// Prepare a timer for the timeout.
	timer := time.NewTimer(time.Until(s.managedReadDeadline()))
	// If the timeout is time.Time{} it's infinite.
	cancel := timer.C
	if deadline.IsZero() {
		c := make(chan time.Time)
		defer close(c) // close c
		cancel = c
	}
	n, err = s.managedRead(b, cancel)
	// Drain timer if necessary.
	if !timer.Stop() && !errors.Contains(err, ErrStreamTimedOut) {
		<-timer.C
	}
	return
}

// RemoteAddr implements net.Conn.
func (s *Stream) RemoteAddr() net.Addr {
	return s.staticMux.staticConn.RemoteAddr()
}

// SetDeadline implements net.Conn.
func (s *Stream) SetDeadline(t time.Time) error {
	err1 := s.SetWriteDeadline(t)
	err2 := s.SetReadDeadline(t)
	return errors.Compose(err1, err2)
}

// SetPriority sets the streams priority. Streams with higher priority will be
// scheduled more often and have therefore lower latency.
// TODO: figure out how to do that
func (s *Stream) SetPriority(priority int) error {
	panic("not implemented yet")
}

// SetReadDeadline implements net.Conn.
func (s *Stream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readDeadline = t
	return nil
}

// SetWriteDeadline implements net.Conn.
func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeDeadline = t
	return nil
}

// Write implements net.Conn by splitting up the data into frames, encrypting
// them and sending them over the wire one-by-one. Currently there is no
// prioritization and all calls to Write fight for the same lock to send the
// data. They will only send one frame per acquired lock though.
func (s *Stream) Write(b []byte) (n int, err error) {
	// Check if stream is closed.
	select {
	case <-s.staticCtx.Done():
		s.mu.Lock()
		err = s.closedErr
		s.mu.Unlock()
		return 0, errors.Compose(io.ErrClosedPipe, err)
	default:
	}
	// Check deadline before starting write.
	deadline := s.managedWriteDeadline()
	if !deadline.IsZero() && time.Now().After(deadline) {
		return 0, ErrStreamTimedOut
	}
	// Prepare a timer for the timeout.
	timer := time.NewTimer(time.Until(s.managedWriteDeadline()))
	// If the timeout is time.Time{} it's infinite.
	cancel := timer.C
	if deadline.IsZero() {
		c := make(chan time.Time)
		defer close(c) // close c
		cancel = c
	}
	// If we got some data in the buffer, use it.
	s.mu.Lock()
	lazyN := len(s.lazyBuf)
	if lazyN > 0 {
		b = append(s.lazyBuf, b...)
		s.lazyBuf = nil
	}
	s.mu.Unlock()
	n, err = s.staticMux.managedWrite(b, s, cancel)

	// Adjust n.
	if n >= lazyN {
		n -= lazyN
	}

	// Drain timer if necessary.
	if !timer.Stop() && !errors.Contains(err, ErrStreamTimedOut) {
		<-timer.C
	}
	return
}

// managedReadDeadline returns the stream's read deadline.
func (s *Stream) managedReadDeadline() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readDeadline
}

// managedWriteDeadline returns the stream's write deadline.
func (s *Stream) managedWriteDeadline() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeDeadline
}

// managedRead implements net.Conn by reading from a reader which is fed by the
// data fetching background thread of the mux. If no data is available Read will
// block. If data is available and not read, other streams of the same
// connection will be blocked as well.
func (s *Stream) managedRead(b []byte, timeout <-chan time.Time) (n int, err error) {
	// If we got a partial frame buffered use that. Don't check the timeout
	// since the data is already cached anyway.
	s.mu.Lock()
	n = copy(b, s.partialFrame)
	if len(s.partialFrame) > 0 && n < len(b) {
		s.partialFrame = nil
		s.mu.Unlock()
		return
	} else if len(s.partialFrame) > 0 && n == len(b) {
		s.partialFrame = s.partialFrame[n:]
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	// Check if we timed out or not.
	var payload []byte
	select {
	case <-timeout:
		return 0, ErrStreamTimedOut
	case <-s.staticCtx.Done():
		err = io.ErrClosedPipe
	case payload = <-s.staticPayloadChan:
		n = copy(b, payload)
	}
	s.mu.Lock()
	err = errors.Compose(err, s.closedErr)
	if n < len(payload) {
		s.partialFrame = payload[n:]
	}
	s.mu.Unlock()
	return
}
