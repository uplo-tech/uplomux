package uplomux

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/uplo-tech/errors"
	"github.com/uplo-tech/uplomux/mux"
)

// staticStopped returns 'true' if Close has been called on the UploMux before.
func (sm *UploMux) staticStopped() bool {
	select {
	case <-sm.staticCtx.Done():
		return true
	default:
		return false
	}
}

// NewListener returns a new listener for a given subscriber name.
func (sm *UploMux) NewListener(subscriber string, handler HandlerFunc) error {
	if sm.staticStopped() {
		return errors.New("UploMux has already been closed")
	}
	sm.staticMu.Lock()
	defer sm.staticMu.Unlock()
	// Check if handler already exists.
	_, exists := sm.handlers[subscriber]
	if exists {
		return fmt.Errorf("handler for subscriber %v already registered", subscriber)
	}
	// Register the handler.
	sm.handlers[subscriber] = &Handler{
		staticFunc: handler,
	}
	return nil
}

// CloseListener will close a previously registered listener, causing incoming
// streams for that listener to be dropped with an error.
func (sm *UploMux) CloseListener(subscriber string) error {
	sm.staticMu.Lock()
	handler, exists := sm.handlers[subscriber]
	if !exists {
		sm.staticMu.Unlock()
		return fmt.Errorf("handler for subscriber %v doesn't exist", subscriber)
	}
	// Remove handler.
	delete(sm.handlers, subscriber)
	sm.staticMu.Unlock()
	// Wait for running handlers to return.
	return handler.staticTG.Stop()
}

// spawnListeners will spawn a tcp listener and a minimal http webserver which
// listens for websocket connections. Both types of connections are then
// upgraded using the mux.Mux.
func (sm *UploMux) spawnListeners(tcpAddr, wsAddr string) error {
	err1 := sm.spawnListenerTCP(tcpAddr)
	err2 := sm.spawnListenerWS(wsAddr)
	return errors.Compose(err1, err2)
}

// spawnListenerTCP spawns a listener which listens for raw TCP connections and
// upgrades them using the mux.Mux.
func (sm *UploMux) spawnListenerTCP(address string) error {
	// Listen on the specified address for incoming connections.
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return errors.AddContext(err, "unable to create listener")
	}
	sm.staticListener = listener
	// Spawn the listening thread.
	sm.staticWG.Add(1)
	go func() {
		sm.threadedHandleTCP(listener)
		sm.staticWG.Done()
	}()
	// Spawn a thread to close the listener.
	sm.staticWG.Add(1)
	go func() {
		<-sm.staticCtx.Done()
		err := sm.staticListener.Close()
		if err != nil {
			sm.staticLog.Print("failed to close listener", err)
		}
		sm.staticWG.Done()
	}()
	return nil
}

// spawnListenerWS spawns a minimal web server to listen for incoming websocket
// connections. These are then upgraded to mux.Mux.
func (sm *UploMux) spawnListenerWS(address string) error {
	// Listen on the specified address for incoming connections.
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return errors.AddContext(err, "unable to create listener")
	}
	// Declare a http mux for the http server.
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/", sm.handleWS)
	// Create the http.Server
	server := &http.Server{
		Addr:    listener.Addr().String(),
		Handler: httpMux,
	}
	// Start serving the websocket endpoint.
	sm.staticWG.Add(1)
	go func() {
		defer sm.staticWG.Done()
		err := server.Serve(listener)
		if err != http.ErrServerClosed {
			sm.staticLog.Print("WARNING: websocket server reported error on shutdown:", err)
		}
	}()
	// Spawn a thread to shutdown the server.
	sm.staticWG.Add(1)
	go func() {
		defer sm.staticWG.Done()
		<-sm.staticCtx.Done()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()
		err := server.Shutdown(ctx)
		if err != nil {
			sm.staticLog.Print("WARNING: shutting down the websocket server returned an error:", err)
		}
	}()
	// Set the URL the UploMux is listening on.
	sm.staticURL = fmt.Sprintf("ws://%v", listener.Addr().String())
	return nil
}

// threadedAccept is spawned for every open connection wrapped in a multiplexer.
// It will constantly accept streams on that multiplexer, discard the ones that
// refer to unknown subscribers and forward the other ones to the corresponding
// listener.
func (sm *UploMux) threadedAccept(mux *mux.Mux) {
	defer func() {
		// Remove the mux when we are not accepting streams anymore.
		sm.managedRemoveMux(mux)
		err := mux.Close()
		if err != nil {
			sm.staticLog.Logger.Print("threadedAccept: failed to close mux", err)
		}
	}()
	// Start accepting streams.
	for {
		select {
		case <-sm.staticCtx.Done():
			return // UploMux closed
		default:
		}
		// Accept a stream.
		stream, err := mux.AcceptStream()
		if errors.Contains(err, io.EOF) {
			return
		} else if err != nil {
			sm.staticLog.Print("UploMux: failed to accept stream", err)
			continue
		}
		// Read the subscriber.
		subscriber, err := readSubscriber(stream)
		if err != nil {
			sm.staticLog.Print("UploMux: failed to read subscriber", errors.Compose(err, stream.Close()))
			continue
		}
		// Check if a handler exists for the subscriber.
		sm.staticMu.Lock()
		handler, exists := sm.handlers[subscriber]
		sm.staticMu.Unlock()
		if !exists {
			err = writeSubscriberResponse(stream, errUnknownSubscriber)
			sm.staticLog.Print("UploMux: unknown subscriber", subscriber, errors.Compose(stream.Close()))
			continue
		}
		// Send the 'ok' response.
		srb := bytes.NewBuffer(nil)
		if err := writeSubscriberResponse(srb, nil); err != nil {
			sm.staticLog.Print("UploMux: failed to send subscriber response", errors.Compose(err, stream.Close()))
			continue
		}
		stream.LazyWrite(srb.Bytes())
		// Call the handler in a separate goroutine.
		sm.staticWG.Add(1)
		go func() {
			defer sm.staticWG.Done()
			if err := handler.staticTG.Add(); err != nil {
				return
			}
			defer handler.staticTG.Done()
			handler.staticFunc(stream)
		}()
	}
}
