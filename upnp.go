package uplomux

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/uplo-tech/go-upnp"
	"github.com/uplo-tech/uplomux/build"
)

// managedForwardPort adds a port mapping to the router.
func (sm *UploMux) managedForwardPort(port string, desc string) error {
	if build.Release == build.Testing {
		// Port forwarding functions are frequently unavailable during testing,
		// and the long blocking can be highly disruptive. Under normal
		// scenarios, return without complaint, and without running the
		// port-forward logic.
		return nil
	}

	// If the port is invalid, there is no need to perform any of the other
	// tasks.
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return err
	}

	// Create a context to stop UPnP discovery in case of a shutdown.
	ctx, cancel := context.WithCancel(sm.staticCtx)
	defer cancel()

	// Look for UPnP-enabled devices
	d, err := upnp.DiscoverCtx(ctx)
	if err != nil {
		err = fmt.Errorf("WARN: could not automatically forward port %s: no UPnP-enabled devices found: %v", port, err)
		return err
	}

	// Forward port
	err = d.Forward(uint16(portInt), desc)
	if err != nil {
		err = fmt.Errorf("WARN: could not automatically forward port %s: %v", port, err)
		return err
	}
	return nil
}

// managedClearPort removes a port mapping from the router.
func (sm *UploMux) managedClearPort(port string) error {
	if build.Release == build.Testing {
		return nil
	}

	// 10 seconds timeout to cancel clearing the port. Don't use sm.staticCtx
	// here since this is called on shutdown and it might already be closed or
	// wait for this method to return before closing.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	d, err := upnp.DiscoverCtx(ctx)
	if err != nil {
		return err
	}

	portInt, _ := strconv.Atoi(port)
	err = d.Clear(uint16(portInt))
	if err != nil {
		return err
	}
	return nil
}

// threadedForwardPorts forwards both the TCP and WS ports of the Uplomux in a
// non-blocking way.
func (sm *UploMux) managedForwardPorts(tcpAddr, wsAddr string) {
	// Forward TCP.
	sm.staticWG.Add(1)
	go func() {
		defer sm.staticWG.Done()
		_, port, err := net.SplitHostPort(tcpAddr)
		if err != nil {
			sm.staticLog.Print("WARN: failed to get TCP port: ", err)
			return
		}
		err = sm.managedForwardPort(port, "UploMux TCP")
		if err != nil {
			sm.staticLog.Printf("WARN: failed to forward TCP port '%v': %v", port, err)
			return
		}
		sm.staticLog.Printf("Successfully forwarded TCP port '%v'", port)
	}()
	// Forward WS.
	sm.staticWG.Add(1)
	go func() {
		defer sm.staticWG.Done()
		_, port, err := net.SplitHostPort(wsAddr)
		if err != nil {
			sm.staticLog.Print("WARN: failed to get WS port: ", err)
			return
		}
		err = sm.managedForwardPort(port, "UploMux WS")
		if err != nil {
			sm.staticLog.Printf("WARN: failed to forward WS port '%v': %v", port, err)
			return
		}
		sm.staticLog.Printf("Successfully forwarded WS port '%v'", port)
	}()
}

// managedClearPorts clears the ports of the uplomux.
func (sm *UploMux) managedClearPorts() {
	// Clear TCP port.
	sm.staticWG.Add(1)
	go func() {
		defer sm.staticWG.Done()
		tcpAddr := sm.staticListener.Addr().String()
		_, port, err := net.SplitHostPort(tcpAddr)
		if err != nil {
			sm.staticLog.Printf("failed to get TCP port")
			return
		}
		err = sm.managedClearPort(port)
		if err != nil {
			sm.staticLog.Printf("failed to clear TCP port '%v': %v", port, err)
			return
		}
		sm.staticLog.Printf("Successfully cleared TCP port '%v'", port)
	}()
	// Clear WS port.
	sm.staticWG.Add(1)
	go func() {
		defer sm.staticWG.Done()
		wsURL, err := url.Parse(sm.staticURL)
		if err != nil {
			sm.staticLog.Printf("failed to parse WS url")
			return
		}
		err = sm.managedClearPort(wsURL.Port())
		if err != nil {
			sm.staticLog.Printf("failed to clear WS port '%v': %v", wsURL.Port(), err)
			return
		}
		sm.staticLog.Printf("Successfully cleared WS port '%v'", wsURL.Port())
	}()
}
