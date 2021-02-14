package mux

import (
	"context"
	"crypto/cipher"
	"net"
	"sync"
	"time"

	"github.com/uplo-tech/errors"
	"github.com/uplo-tech/log"
	"github.com/uplo-tech/uplomux/deps"
)

const (
	// DefaultMuxInitTimeout defines the amount of time that is given to the mux
	// to complete init, which includes the encryption handshake.
	DefaultMuxInitTimeout = 5 * time.Minute
)

const (
	// pruneClosedStreamInterval is the interval used to prune the closedStreams
	// map.
	pruneClosedStreamInterval = 10 * time.Minute
	// closedStreamReuseTimeout is the timeout after closing a stream before its
	// id is accepted for establishing a new stream again.
	closedStreamReuseTimeout = 10 * time.Minute

	// ipV4PacketSize is the maximum IPv4 packet size
	ipV4PacketSize = 1460

	// ipV6PacketSize is the maximum IPv6 packet size
	ipV6PacketSize = 1440
)

var (
	// minPacketSize is the minimum allowed packet size which is derived from
	// the IPv6 required link MTU of 1280. 40 bytes of that will be lost to
	// IPv6, and 20 more will be lost to TCP.
	minPacketSize = uint16(1220)

	// minFrameSizePackets is the minimum frame size allowed in number of
	// packets.
	minFrameSizePackets = uint32(1)

	// lowerMaxFrameSizePackets is the minimum maxFrameSize that two peers can
	// agree upon in packets.
	lowerMaxFrameSizePackets = uint32(10)

	// upperMaxFrameSizePackets is the maximum frameSize that two peers can
	// agree upon in packets.
	upperMaxFrameSizePackets = uint32(64)

	// numReservedFrameIDs describes the number of reserved IDs for frames. In
	// other words it's the first frame ID which can be assigned to new streams.
	numReservedFrameIDs = uint32(256)

	// LowerMaxTimeout is the lower bound for the maxTimeout that two peers can
	// agree upon.
	LowerMaxTimeout = uint16(120)
)

var (
	// DefaultMaxTimeout is the default value used for the mux's maxTimeout.
	DefaultMaxTimeout = uint16(1200) // 20 minutes
	// DefaultMaxStreamTimeout is the default value used for an established
	// stream.
	DefaultMaxStreamTimeout = uint16(600) // 10 minutes
)

type (
	// Mux is the underlying multiplexer of the UploMux package. It is used to split
	// up a single net.Conn into multiple streams which also satisfy the net.Conn
	// interface.
	Mux struct {
		staticAead cipher.AEAD
		staticConn net.Conn
		settings   connectionSettings

		// server related fields
		pubKey  ED25519PublicKey
		privKey ED25519SecretKey

		// stream related fields
		streams              map[uint32]*Stream
		newStreams           []*Stream
		nextFrameID          uint32
		staticNewStreamsChan chan struct{}

		closedStreams map[uint32]time.Time

		// staticCloseCallback is called when the mux is closed.
		staticCloseCallback closeCallback

		// staticTimeoutCallback is called when the mux is about to time out.
		timeoutCallbackTime   time.Time
		staticTimeoutCallback timeoutCallback
		staticTimeoutChanged  chan struct{}

		// protocol version used
		staticVersion byte

		// utilities
		staticDeps      deps.Dependencies
		staticCtx       context.Context
		staticCtxCancel context.CancelFunc
		staticLog       *log.Logger
		staticMu        sync.Mutex
		staticWG        sync.WaitGroup
	}
	// connectionSettings contains settings related to the settings like the
	// negotiated packet size or connection timeout.
	connectionSettings struct {
		// Different connections are going to have different optimal packet sizes.
		// Typically, for IPv4-TCP connections, the optimal packet size is going to
		// be 1460 bytes, and for IPv6-TCP connections, the optimal packet size is
		// going to be 1440 bytes.
		//
		// These numbers are derived from the fact that Ethernetv2 packets generally
		// have an MTU of 1500 bytes. 20 bytes goes to IPv4 headers, 40 bytes
		// goes to IPv6 headers, and 20 bytes goes to TCP headers.
		//
		// The requestedPacketSize is not allowed to be smaller than 1220 bytes.
		// This is derived from the IPv6 required link MTU of 1280. 40 bytes of that
		// will be lost to IPv6, and 20 more will be lost to TCP.
		//
		RequestedPacketSize uint16

		// MaxFrameSize establishes the maximum size in packets that the mux
		// will expect for an encrypted frame. If a larger frame is sent, the
		// mux connection will be closed.
		//
		// A typical maximum frame size is 64 packets. Generally frame sizes are
		// going to be small so that streams can be intertwined, and so that it is
		// easy to interrupt a low priority stream with a sudden high priority
		// stream. This value must be at least 16 packets.
		MaxFrameSizePackets uint32

		// MaxTimeout defines the maximum timeout that the mux peer is
		// willing to accept for the connection. Keepalives need to be sent at least
		// this often.
		MaxTimeout uint16
	}
	// closeCallback is the signature of a method which will be called when a
	// mux is closed but before the underlying connection is closed.
	closeCallback func(*Mux)
	// timeoutCallback is the signature of a method used as the timeout callback
	// of the mux. A method called before a mux is about to time out.
	timeoutCallback func(*Mux)
)

// MaxFrameSize is a helper that returns the negotiated MaxFrameSize in bytes.
func (cs *connectionSettings) MaxFrameSize() uint32 {
	return cs.MaxFrameSizePackets * uint32(cs.RequestedPacketSize)
}

// defaultConnectionSettings are the default settings set by a mux on
// creation.
func defaultConnectionSettings(conn net.Conn) (connectionSettings, error) {
	var packetSize uint16
	// Figure out if connection's ip is IPv4 or IPv6
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return connectionSettings{}, err
	}
	ip := net.ParseIP(host)
	if ip.To4() != nil {
		packetSize = ipV4PacketSize // IPv4
	} else if ip.To16() != nil {
		packetSize = ipV6PacketSize // IPv6
	} else {
		return connectionSettings{}, errors.New("invalid ip address")
	}
	return connectionSettings{
		RequestedPacketSize: packetSize,
		MaxFrameSizePackets: lowerMaxFrameSizePackets, // 10 packets
		MaxTimeout:          DefaultMaxTimeout,        // 20 minutes
	}, nil
}

// newMux wraps a net.Conn in a multiplexer and will immediately begin to
// upgrade the connection to an encrypted one.
func newMux(ctx context.Context, conn net.Conn, pubKey ED25519PublicKey, privKey ED25519SecretKey, outgoing bool, log *log.Logger, f closeCallback, t timeoutCallback) (_ *Mux, err error) {
	connSettings, err := defaultConnectionSettings(conn)
	if err != nil {
		return nil, err
	}
	context, cancel := context.WithCancel(ctx)
	defer func() {
		if err != nil {
			cancel()
		}
	}()
	// Figure out the frame id to start with.
	nextFrameID := numReservedFrameIDs
	if !outgoing {
		nextFrameID++
	}
	mux := &Mux{
		nextFrameID: nextFrameID,
		staticDeps:  deps.ProdDependencies,
		staticLog:   log,
		staticConn:  conn,
		settings:    connSettings,
		// server related fields
		pubKey:                pubKey,
		privKey:               privKey,
		staticCtx:             context,
		staticCtxCancel:       cancel,
		streams:               make(map[uint32]*Stream),
		closedStreams:         make(map[uint32]time.Time),
		staticCloseCallback:   f,
		staticNewStreamsChan:  make(chan struct{}, 100),
		staticTimeoutCallback: t,
		staticTimeoutChanged:  make(chan struct{}, 1),
		timeoutCallbackTime:   time.Now().Add(time.Duration(connSettings.MaxTimeout) * time.Second),
	}

	// Set a deadline on the conn for completing the handshake.
	err = mux.staticConn.SetDeadline(time.Now().Add(DefaultMuxInitTimeout))
	if err != nil {
		return nil, err
	}

	// Spawn thread to call timeout callback whenever mux is about to time out.
	mux.staticWG.Add(1)
	go func() {
		mux.threadedHandleMaxTimeoutCallback()
		mux.staticWG.Done()
	}()
	// Spawn thread to prune closedStreams map.
	mux.staticWG.Add(1)
	go func() {
		mux.threadedPruneClosedStreams()
		mux.staticWG.Done()
	}()
	// Spawn thread to close the connection when the mux is stopped.
	mux.staticWG.Add(1)
	go func() {
		<-context.Done()
		err := mux.staticConn.Close()
		if err != nil {
			mux.staticLog.Print("failed to close connection", err)
		}
		mux.staticCloseCallback(mux)
		mux.staticWG.Done()
	}()
	return mux, nil
}

// NewClientMux wraps a connection in a Mux and immediately initializes the
// handshake to establish an encrypted connection.
func NewClientMux(ctx context.Context, conn net.Conn, expectedPubKey ED25519PublicKey, log *log.Logger, f closeCallback, t timeoutCallback) (_ *Mux, err error) {
	// client doesn't need the pubKey and privKey since it doesn't need to sign
	// the encryptionResponse.
	mux, err := newMux(ctx, conn, ED25519PublicKey{}, ED25519SecretKey{}, true, log, f, t)
	if err != nil {
		return nil, errors.AddContext(err, "failed to create new client mux")
	}
	defer func() {
		if err != nil {
			err = errors.Compose(err, mux.Close())
		}
	}()
	// init client side connection
	if err := mux.initClient(expectedPubKey); err != nil {
		return nil, errors.AddContext(err, "failed to init client connection")
	}
	// start the background thread.
	mux.staticWG.Add(1)
	go func() {
		mux.threadedReceiveData()
		mux.staticWG.Done()
	}()
	return mux, nil
}

// NewServerMux wraps a connection in a Mux and starts waiting for the peer to
// start initializing the handshake to establish an encrypted connection.
func NewServerMux(ctx context.Context, conn net.Conn, pubKey ED25519PublicKey, privKey ED25519SecretKey, log *log.Logger, f closeCallback, t timeoutCallback) (_ *Mux, err error) {
	// server doesn't need the expectedPubKey since the client's key is ephemeral.
	mux, err := newMux(ctx, conn, pubKey, privKey, false, log, f, t)
	if err != nil {
		return nil, errors.AddContext(err, "failed to create new server mux")
	}
	defer func() {
		if err != nil {
			err = errors.Compose(err, mux.Close())
		}
	}()
	// init server side connection
	if err := mux.initServer(); err != nil {
		return nil, errors.AddContext(err, "failed to init server connection")
	}
	// start the background thread.
	mux.staticWG.Add(1)
	go func() {
		mux.threadedReceiveData()
		mux.staticWG.Done()
	}()
	return mux, nil
}

// Keepalive sends a keepalive frame which updates the timeout on both peers.
func (m *Mux) Keepalive() error {
	return m.managedWriteKeepaliveFrame()
}

// Close closes the mux and waits for background threads to finish.
func (m *Mux) Close() error {
	m.staticCtxCancel()
	m.staticWG.Wait()
	return nil
}

// Idle returns true if the mux currently has no open streams.
func (m *Mux) Idle() bool {
	m.staticMu.Lock()
	defer m.staticMu.Unlock()
	return len(m.streams)+len(m.newStreams) == 0
}

// newFrameID returns an unused frame id. The stream with the returned id needs
// to be added to m.streams right away without unlocking the mutex in the
// meantime. Otherwise a subsequent call to this method might returns the same
// id again.
func (m *Mux) newFrameID() uint32 {
	// Helper to fetch the nextID, handle overflows and increment the field.
	nextID := func() uint32 {
		id := m.nextFrameID
		m.nextFrameID += 2

		// Handle overflow.
		if id < numReservedFrameIDs {
			id += numReservedFrameIDs
			m.nextFrameID += numReservedFrameIDs
		}
		return id
	}

	// Retry until we get an id that's not taken.
	id := nextID()
	for {
		_, taken := m.streams[id]
		_, taken2 := m.closedStreams[id]
		if taken || taken2 {
			id = nextID()
			continue
		}
		return id
	}
}

// threadedPruneClosedStreams periodically prunes the closedStream map to allow
// for used frameIDs to be reused.
func (m *Mux) threadedPruneClosedStreams() {
	for {
		timer := time.NewTimer(pruneClosedStreamInterval)
		select {
		case <-m.staticCtx.Done():
			if !timer.Stop() {
				<-timer.C // drain timer
			}
			return // shutdown
		case <-timer.C:
		}
		m.staticMu.Lock()
		for frameID, closingTime := range m.closedStreams {
			if time.Since(closingTime) > closedStreamReuseTimeout {
				delete(m.closedStreams, frameID)
			}
		}
		m.staticMu.Unlock()
	}
}
