package mux

import (
	"io"
	"io/ioutil"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/uplo-tech/errors"
)

var (
	// ErrUnsupportedMSGType is returned if a message with an unsupported type
	// is received.
	ErrUnsupportedMSGType = errors.New("unsupported message type")
)

// WSConn is a wrapper for a websocket.Conn which allows for it to be used as a
// net.Conn within the Uplomux.
type WSConn struct {
	*websocket.Conn

	currentReader io.Reader
	staticReadMu  sync.Mutex
	staticWriteMu sync.Mutex
}

// NewWSConn wraps a websocket.Conn in a WSConn.
func NewWSConn(conn *websocket.Conn) net.Conn {
	return newWSConn(conn)
}

// newWSConn wraps a websocket.Conn in a WSConn.
func newWSConn(conn *websocket.Conn) *WSConn {
	return &WSConn{Conn: conn}
}

// SetReadDeadline sets the read deadline.
// NOTE: This happens in a goroutine to not be blocked by ongoing reads
// potentially causing deadlocks.
func (wsc *WSConn) SetReadDeadline(t time.Time) error {
	go func() {
		wsc.staticReadMu.Lock()
		_ = wsc.Conn.SetReadDeadline(t)
		wsc.staticReadMu.Unlock()
	}()
	return nil
}

// SetWriteDeadline sets the write deadline.
// NOTE: This happens in a goroutine to not be blocked by ongoing writes
// potentially causing deadlocks.
func (wsc *WSConn) SetWriteDeadline(t time.Time) error {
	go func() {
		wsc.staticWriteMu.Lock()
		_ = wsc.Conn.SetWriteDeadline(t)
		wsc.staticWriteMu.Unlock()
	}()
	return nil
}

// SetDeadline implements the net.Conn interface.
func (wsc *WSConn) SetDeadline(t time.Time) error {
	err1 := wsc.SetReadDeadline(t)
	err2 := wsc.SetWriteDeadline(t)
	return errors.Compose(err1, err2)
}

// Read implements the io.Reader interface. It will treat multiple messages as a
// continuous stream of data if necessary. In the UploMux, the size of the frames
// is known beforehand so every call to Read should only ever require a single
// message.
func (wsc *WSConn) Read(b []byte) (n int, err error) {
	wsc.staticReadMu.Lock()
	defer wsc.staticReadMu.Unlock()

	// Get a reader. Either reuse the current one or get a new one.
	if wsc.currentReader == nil {
		var mt int
		mt, wsc.currentReader, err = wsc.NextReader()
		if err != nil {
			return
		}
		// Make sure the message type is binary. If it is not, we drain it just to
		// be safe and return an error.
		if mt != websocket.BinaryMessage {
			_, err = io.Copy(ioutil.Discard, wsc.currentReader)
			return 0, errors.Compose(err, ErrUnsupportedMSGType)
		}
	}
	// Read from the message.
	n, err = wsc.currentReader.Read(b)
	if err == io.EOF {
		// ignore io.EOF. That just means we have reached the end of the message
		// and might need to call NextReader again.
		err = nil
		wsc.currentReader = nil
	}
	return
}

// Write implements the io.Writer interface. Every call to Write will create a
// new binary websocket message and send it.
func (wsc *WSConn) Write(b []byte) (int, error) {
	wsc.staticWriteMu.Lock()
	defer wsc.staticWriteMu.Unlock()
	w, err := wsc.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return 0, err
	}
	n, err := w.Write(b)
	if err != nil {
		errClose := w.Close()
		return n, errors.Compose(err, errClose)
	}
	return n, w.Close()
}
