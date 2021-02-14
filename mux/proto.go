package mux

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/uplo-tech/encoding"
	"github.com/uplo-tech/errors"
)

var (
	errSmallPacketSize         = errors.New("packetSize < minPacketSize")
	errSmallFrameSize          = errors.New("frameSize < lowerFrameSize")
	errBigFrameSize            = errors.New("frameSize > upperFrameSize")
	errSmallMaxTimeout         = errors.New("maxTimeout < lowerMaxTimeout")
	errSmallStreamTimeout      = errors.New("maxStreamTimeout < lowerStreamTimeout")
	errStreamTimeoutSmallerMax = errors.New("maxTimeout < maxStreamTimeout")

	// ErrInvalidVersion is the error returned when an unknown version number is
	// encountered during the initial handshake.
	ErrInvalidVersion = errors.New("Invalid version number")

	// Version is the current protocol version implemented by this mux.
	Version = byte(1)
)

// mergeConnSettings takes 2 sets of settings and merges them into one. The
// resulting connections are the agreed upon ones between client and server.
func mergeConnSettings(settings1, settings2 connectionSettings) (connectionSettings, error) {
	// Agree upon the smaller packet size as long as it's not below the minimum.
	packetSize := settings1.RequestedPacketSize
	if settings2.RequestedPacketSize < settings1.RequestedPacketSize {
		packetSize = settings2.RequestedPacketSize
	}
	if packetSize < minPacketSize {
		return connectionSettings{}, errors.Compose(errSmallPacketSize, fmt.Errorf("%v < %v", packetSize, minPacketSize))
	}
	// Agree upon the lower frameSize which should be between 1 and 64 packets.
	frameSizePackets := settings1.MaxFrameSizePackets
	if settings2.MaxFrameSizePackets < settings1.MaxFrameSizePackets {
		frameSizePackets = settings2.MaxFrameSizePackets
	}
	if frameSizePackets < lowerMaxFrameSizePackets {
		return connectionSettings{}, errors.Compose(errSmallFrameSize, fmt.Errorf("%v < %v", frameSizePackets, lowerMaxFrameSizePackets))
	}
	if frameSizePackets > upperMaxFrameSizePackets {
		return connectionSettings{}, errors.Compose(errBigFrameSize, fmt.Errorf("%v < %v", frameSizePackets, upperMaxFrameSizePackets))
	}
	// Agree upon the lower MaxTimeout.
	maxTimeout := settings1.MaxTimeout
	if settings2.MaxTimeout < settings1.MaxTimeout {
		maxTimeout = settings2.MaxTimeout
	}
	if maxTimeout < LowerMaxTimeout {
		return connectionSettings{}, errors.Compose(errSmallMaxTimeout, fmt.Errorf("%v < %v", maxTimeout, LowerMaxTimeout))
	}
	return connectionSettings{
		RequestedPacketSize: packetSize,
		MaxFrameSizePackets: frameSizePackets,
		MaxTimeout:          maxTimeout,
	}, nil
}

// initClient does the initialization for a new client mux. This consists of
// establishing encryption and sending the first updateSettingsFrame.
func (m *Mux) initClient(expectedPubKey ED25519PublicKey) error {
	if err := m.initVersionClient(); err != nil {
		return err
	}
	if err := m.initEncryptionClient(expectedPubKey); err != nil {
		return err
	}
	return m.initUpdateSettingsClient()
}

// initServer does the initialization for a new server mux. This consists of
// establishing encryption and receiving the first updateSettingsFrame from the
// client.
func (m *Mux) initServer() error {
	if err := m.initVersionServer(); err != nil {
		return err
	}
	if err := m.initEncryptionServer(); err != nil {
		return err
	}
	return m.initUpdateSettingsServer()
}

// initEncryptionClient sends an encryption request frame with an ephemeral key
// to the server and performs the key exchange necessary to upgrade the
// connection to an encrypted connection.
func (m *Mux) initEncryptionClient(expectedPubKey ED25519PublicKey) error {
	// Create the request for the handshake.
	requestSecretKey, requestPublicKey, eerf := newEstablishEncryptionRequestFrame()
	// Marshal the frame.
	f, err := eerf.Marshal()
	if err != nil {
		return errors.AddContext(err, "failed to marshal encryptionRequest frame")
	}
	// Send the frame.
	_, err = m.staticConn.Write(f)
	if err != nil {
		return errors.AddContext(err, "failed to send encryptionRequest frame")
	}
	// Receive the response.
	resp := make([]byte, marshaledEstablishEncryptionResponseFrameSize)
	_, err = io.ReadFull(m.staticConn, resp)
	if err != nil {
		return errors.AddContext(err, "failed to read encryptionResponse frame")
	}
	// Unmarshal the response frame.
	var respFrame frame
	if err := respFrame.Unmarshal(resp); err != nil {
		return errors.AddContext(err, "failed to unmarshal response frame")
	}
	// Check that the correct flag was set.
	if respFrame.id != frameIDEstablishEncryption {
		return fmt.Errorf("expected response frame to have flag %v but was %v", frameIDEstablishEncryption, respFrame.id)
	}
	// Unmarshal the establishEncryptionResponse.
	var eer establishEncryptionResponse
	if err := encoding.Unmarshal(respFrame.payload, &eer); err != nil {
		return errors.AddContext(err, "failed to unmarshal establishEncryptionResponse")
	}
	// verify the signature
	// TODO: If this fails, the host either constructed the wrong hash or signed
	// the hash with the wrong key. No way to tell exactly. All we know is that
	// the host is not authenticated which might be good enough. We can still
	// upgrade the connection to be encrypted.
	hash := createSignatureHash(eer.PublicKey, requestPublicKey)
	if !verifyHash(hash, expectedPubKey, eer.Signature) {
		err = fmt.Errorf("invalid signature for expected key '%v'", hex.EncodeToString(expectedPubKey[:]))
		m.staticLog.Print("ERROR: ", err)
		return err
	}
	// Derive the shared key and prepare the cipher.
	sharedSecret := deriveSharedSecret(requestSecretKey, X25519PublicKey(eer.PublicKey))
	m.staticAead, err = initCipher(sharedSecret[:], eer.Cipher)
	if err != nil {
		return errors.AddContext(err, "failed to init cipher")
	}
	return nil
}

// initEncryptionServer waits for the encryption request from the client to
// perform the key exchange required to upgrade the connection to an encryption
// connection.
func (m *Mux) initEncryptionServer() error {
	// Receive the establishEncryptionRequestFrame.
	reqFrameData := make([]byte, marshaledEstablishEncryptionRequestFrameSize)
	if _, err := io.ReadFull(m.staticConn, reqFrameData); err != nil {
		return errors.AddContext(err, "failed to read establishEncryptionRequestFrame")
	}
	// Unmarshal the request frame.
	var reqFrame frame
	if err := reqFrame.Unmarshal(reqFrameData); err != nil {
		return errors.AddContext(err, "failed to unmarshale establishEncryptionRequestFrame")
	}
	// Check that the correct flag was set.
	if reqFrame.id != frameIDEstablishEncryption {
		return fmt.Errorf("expected request frame to have flag %v but was %v", frameIDEstablishEncryption, reqFrame.id)
	}
	// Unmarshal the establishEncryptionRequest.
	var eer establishEncryptionRequest
	if err := encoding.Unmarshal(reqFrame.payload, &eer); err != nil {
		return errors.AddContext(err, "failed to unmarshal establishEncryptionRequest")
	}
	// Prepare the response.
	xsk, cipher, respFrame := newEstablishEncryptionResponseFrame(eer.PublicKey, m.privKey)
	// Marshal the response.
	respFrameData, err := respFrame.Marshal()
	if err != nil {
		return errors.AddContext(err, "failed to marshal response frame")
	}
	// Send response.
	if _, err := m.staticConn.Write(respFrameData); err != nil {
		return errors.AddContext(err, "failed to send response frame")
	}
	// Derive the shared key
	sharedSecret := deriveSharedSecret(xsk, eer.PublicKey)
	m.staticAead, err = initCipher(sharedSecret[:], cipher)
	if err != nil {
		return errors.AddContext(err, "failed to init cipher")
	}
	return nil
}

// initUpdateSettingsClient sends the first updateSettingsFrame to the server to
// initialize the connection.
func (m *Mux) initUpdateSettingsClient() error {
	// Create the updateSettingsFrame and send it to the server.
	clientSettings := newUpdateConnectionSettingsFrame(m.settings)
	if _, err := m.managedWriteFrame(clientSettings); err != nil {
		return errors.AddContext(err, "client failed to write clientSettings")
	}
	// Read the server settings.
	_, serverSettings, err := m.managedReadFrame()
	if err != nil {
		return errors.AddContext(err, "client failed to read serverSettings frame")
	}
	if serverSettings.id != frameIDUpdateSettings {
		return fmt.Errorf("expected frameID to be %v but was %v", frameIDUpdateSettings, serverSettings.id)
	}
	var settings connectionSettings
	if err := encoding.Unmarshal(serverSettings.payload, &settings); err != nil {
		return errors.AddContext(err, "failed to unmarshal connection settings")
	}
	// Merge client and server settings.
	m.settings, err = mergeConnSettings(m.settings, settings)
	return err
}

// initUpdateSettingsServer receives the first updateSettingsFrame from the
// client to initialize the connection.
func (m *Mux) initUpdateSettingsServer() error {
	// Read the settings frame.
	_, clientSettings, err := m.managedReadFrame()
	if err != nil {
		return errors.AddContext(err, "failed to read clientSettings frame")
	}
	if clientSettings.id != frameIDUpdateSettings {
		return fmt.Errorf("expected frameID to be %v but was %v", frameIDUpdateSettings, clientSettings.id)
	}
	var settings connectionSettings
	if err := encoding.Unmarshal(clientSettings.payload, &settings); err != nil {
		return errors.AddContext(err, "failed to unmarshal connection settings")
	}
	// Respond with own settings.
	serverSettings := newUpdateConnectionSettingsFrame(m.settings)
	if _, err := m.managedWriteFrame(serverSettings); err != nil {
		return errors.AddContext(err, "client failed to write serverSettings")
	}
	// Merge client and server settings.
	m.settings, err = mergeConnSettings(m.settings, settings)
	return err
}

// initVersionServer conducts the version handshake for the client.
func (m *Mux) initVersionClient() error {
	// Send version 1. The only supported version right now.
	if _, err := m.staticConn.Write([]byte{Version}); err != nil {
		return errors.AddContext(err, "failed to send client version")
	}
	// Receive the version byte.
	peerVersion := make([]byte, 1)
	if _, err := io.ReadFull(m.staticConn, peerVersion); err != nil {
		return errors.AddContext(err, "failed to read version byte")
	}
	// Make sure the version is not 0.
	if peerVersion[0] == 0 {
		return ErrInvalidVersion
	}
	// Set the version.
	if peerVersion[0] < Version {
		m.staticVersion = peerVersion[0]
	} else {
		m.staticVersion = Version
	}
	return nil
}

// initVersionServer conducts the version handshake for the server.
func (m *Mux) initVersionServer() error {
	// Receive the version byte.
	peerVersion := make([]byte, 1)
	if _, err := io.ReadFull(m.staticConn, peerVersion); err != nil {
		return errors.AddContext(err, "failed to read version byte")
	}
	// Make sure the version is not 0.
	if peerVersion[0] == 0 {
		return ErrInvalidVersion
	}
	// Send back our own version.
	if _, err := m.staticConn.Write([]byte{Version}); err != nil {
		return errors.AddContext(err, "failed to respond with server version")
	}
	// Set the version.
	if peerVersion[0] < Version {
		m.staticVersion = peerVersion[0]
	} else {
		m.staticVersion = Version
	}
	return nil
}

// managedAcceptStream listens for an incoming stream and returns it. If the mux
// is stopped while waiting for a new stream, 'nil' is returned.
func (m *Mux) managedAcceptStream() (s *Stream, err error) {
	// Wait for a stream to be available.,
	select {
	case <-m.staticCtx.Done():
		return nil, io.EOF
	case <-m.staticNewStreamsChan:
	}

	// Grab it.
	m.staticMu.Lock()
	defer m.staticMu.Unlock()
	if len(m.newStreams) == 0 {
		err := errors.New("m.newStreams shouldn't have len 0")
		m.staticLog.Severe(err)
		return nil, err
	}
	s, m.newStreams = m.newStreams[0], m.newStreams[1:]
	return s, nil
}

// managedReadFrame updates the deadline on the connection and reads a frame
// from the mux's underlying connection.
func (m *Mux) managedReadFrame() (int, frame, error) {
	// Grab settings.
	m.staticMu.Lock()
	conn, aead, maxFrameSizePackets, packetSize := m.staticConn, m.staticAead, m.settings.MaxFrameSizePackets, uint32(m.settings.RequestedPacketSize)
	m.staticMu.Unlock()

	// Read frame.
	maxEncryptedFrameSize := maxFrameSizePackets * packetSize
	n, f, _, err := readFrame(conn, aead, maxEncryptedFrameSize, packetSize)
	if err != nil {
		return 0, frame{}, errors.AddContext(err, "failed to read frame")
	}

	// Update the deadline only on success. Otherwise if a connection is very
	// slow, new calls to managedReadFrame or managedWriteFrame will extend the
	// deadline. So as long as we have incoming calls, we will never time out.
	m.staticMu.Lock()
	err = m.updateDeadline()
	m.staticMu.Unlock()
	return n, f, err
}

// managedWriteFrame updates the deadline on the connection and writes a
// frame directly to the mux's underlying connection. This method doesn't use
// the background sender thread and can be used before the mux is fully
// initialised. Returns the number of bytes written.
func (m *Mux) managedWriteFrame(f frame) (int, error) {
	// Grab settings.
	m.staticMu.Lock()
	conn, aead, maxFrameSizePackets, packetSize := m.staticConn, m.staticAead, m.settings.MaxFrameSizePackets, uint32(m.settings.RequestedPacketSize)
	m.staticMu.Unlock()

	// Write frame.
	n, err := writeFrame(conn, aead, f, minFrameSizePackets, maxFrameSizePackets, packetSize)
	if err != nil {
		return n, err
	}

	// Update deadline only on success. Otherwise if a connection is very slow,
	// new calls to managedReadFrame or managedWriteFrame will extend the
	// deadline. So as long as we have incoming calls, we will never time out.
	m.staticMu.Lock()
	err = m.updateDeadline()
	m.staticMu.Unlock()
	return n, err
}

// requiredPackets returns the number of packets required to send a payload of a
// certain length and the leftover available space in the last packet.
func requiredPackets(payloadLen, packetSize uint32, aead cipher.AEAD) (numPackets, leftoverBytes uint32) {
	// calculate the encryption overhead twice because the header and the
	// payload are encrypted separately.
	encryptedFrameSize := marshaledFrameHeaderSize + payloadLen + uint32(2*aead.NonceSize()+2*aead.Overhead())
	numPackets = encryptedFrameSize / packetSize
	if encryptedFrameSize%packetSize != 0 {
		numPackets++
	}
	leftoverBytes = numPackets*packetSize - encryptedFrameSize
	return numPackets, leftoverBytes
}

// managedWrite splits up the provided data into frames with the specified id
// and writes them to the underlying connection, blocking until all frames are
// written.
func (m *Mux) managedWrite(b []byte, s *Stream, timeout <-chan time.Time) (int, error) {
	id := s.staticID
	// Split the data up into frames.
	m.staticMu.Lock()
	maxPayload := maxFramePayloadSize(m.settings.MaxFrameSize(), m.staticAead) - marshaledFrameHeaderSize
	packetSize := uint32(m.settings.RequestedPacketSize)
	m.staticMu.Unlock()

	// Force a timeout using the dependency.
	m.staticDeps.Disrupt("delayWrite")

	// Start writing the data frame by frame.
	buf := bytes.NewBuffer(b)
	var written int
	for payload := buf.Next(maxPayload); len(payload) > 0; payload = buf.Next(maxPayload) {
		m.staticDeps.Disrupt("slowWrite")
		// Record the upload
		requiredPackets, _ := requiredPackets(uint32(len(payload)), packetSize, m.staticAead)
		err := s.managedRecordUpload(uint64(requiredPackets * packetSize))
		if err != nil {
			errWriteErr := m.managedWriteErrorFrame(s.staticID, err)
			_, errRemove := m.managedRemoveStream(s.staticID, err)
			err = errors.Compose(err, errWriteErr, errRemove)
			m.staticLog.Print("failed to write error frame:", err)
			return written, err
		}

		// Check for a timeout or a closed stream.
		select {
		case <-timeout:
			return written, ErrStreamTimedOut
		case <-s.staticCtx.Done():
			return written, errors.Compose(io.ErrClosedPipe, s.closedErr)
		default:
		}

		// Write the frame.
		f := newPayloadFrame(id, payload)
		_, err = m.managedWriteFrame(f)
		if err != nil {
			return written, err
		}
		written += len(payload)
	}
	return len(b), nil
}

// managedRemoveStream closes a stream and removes it from the Mux.
func (m *Mux) managedRemoveStream(frameID uint32, err error) (bool, error) {
	m.staticMu.Lock()
	m.closedStreams[frameID] = time.Now()
	// Search established streams.
	stream, exists := m.streams[frameID]
	if exists {
		delete(m.streams, frameID)
		m.staticMu.Unlock()
		return true, stream.managedClose(err)
	}
	m.staticMu.Unlock()
	return false, nil
}

// managedWriteErrorFrame is a convenience method to create an error frame from
// a given id and error and write it to the underlying connection of the mux.
func (m *Mux) managedWriteErrorFrame(id uint32, err error) error {
	ef := newErrorFrame(id, err)
	_, err = m.managedWriteFrame(ef)
	return err
}

// managedWriteFinalFrame is a convenience method to create a frame from a given
// id with the finalFrame flag set and write it to the underlying connection of
// the mux.
func (m *Mux) managedWriteFinalFrame(id uint32) error {
	ef := newFinalFrame(id)
	_, err := m.managedWriteFrame(ef)
	return err
}

// managedWriteKeepaliveFrame writes a keepalive frame with the corresponding id
// to the underlying connection of the mux.
func (m *Mux) managedWriteKeepaliveFrame() error {
	kf := newKeepaliveFrame()
	_, err := m.managedWriteFrame(kf)
	return err
}

// threadedReceiveData is a background thread which keeps fetching data from the
// mux's underlying connection.
func (m *Mux) threadedReceiveData() {
	// Make sure the mux gets closed when this loop exits.
	defer m.staticCtxCancel()

	// Start the loop.
	for {
		select {
		case <-m.staticCtx.Done():
			return // mux was stopped
		default:
		}
		readData, frame, err := m.managedReadFrame()
		if err, ok := err.(net.Error); ok && err.Timeout() {
			m.staticLog.Print("connection timed out:", err)
			return
		} else if ok {
			m.staticLog.Debug("readFrame failed due to connection error:", err)
			return
		}
		if errors.Contains(err, io.EOF) {
			m.staticLog.Debug("readFrame failed due to io.EOF: ", err)
			return
		}
		if err != nil {
			m.staticLog.Print("readFrame failed:", err)
			return
		}
		// Check for special flags.
		finalFrame := frame.flags&frameBitFinalFrame > 0
		errorFrame := frame.flags&frameBitErrorFrame > 0

		// Check if errorFrame bit was set correctly and handle it.
		if errorFrame {
			if !finalFrame {
				err = errors.New("can't set errorFrame bit without finalFrame bit")
			}
			if err != nil {
				m.staticLog.Print(err)
			}
		}
		// Check if it is necessary to close the stream.
		if finalFrame || errorFrame {
			// Return io.ErrClosedPipe for a finalFrame and the payload of the
			// error frame for an errorFrame.
			respErr := io.ErrClosedPipe
			if errorFrame {
				respErr = errors.New(string(frame.payload))
			}
			removed, err := m.managedRemoveStream(frame.id, respErr) // either error from above if flags were inconsistent or io.EOF on 'nil'
			if err != nil {
				m.staticLog.Debug("failed to remove stream:", err)
				continue
			}
			if !removed {
				m.staticLog.Debug("stream to remove wasn't found:", frame.id)
				continue
			}
			m.staticLog.Debug("stream removed successfully:", finalFrame, errorFrame, frame.id)
			continue
		}
		// Check for special ids.
		switch frame.id {
		case frameIDUpdateSettings:
			// TODO (followup): update settings. can this be done by both peers?
			continue
		case frameIDKeepalive:
			continue
		default:
		}
		// Send back an error with the same frame id set.
		if frame.id == frameIDErrorBadInit || frame.id < numReservedFrameIDs {
			err := m.managedWriteErrorFrame(frame.id, errors.New("unknown frame id"))
			if err != nil {
				m.staticLog.Print("failed to write error frame:", err)
			}
			continue
		}
		// Handle regular frame. If the id exists already, write the data to the
		// streams buffer. If not, create a new stream.
		m.staticMu.Lock()
		stream, exists := m.streams[frame.id]
		if !exists {
			// don't create new streams when they reuse the ID of an old stream.
			// Nothing is listening on that stream anymore and opening a new one
			// might result in corrupted data.
			if _, exists := m.closedStreams[frame.id]; exists {
				m.staticMu.Unlock()
				continue
			}
			stream = m.newStream(m.staticCtx, frame.id)
			// add stream to newStreams slice.
			m.newStreams = append(m.newStreams, stream)
			// signal that a new stream was added.
			m.staticMu.Unlock()
			select {
			case <-m.staticCtx.Done():
				return // mux stopped
			case m.staticNewStreamsChan <- struct{}{}:
			}
		} else {
			m.staticMu.Unlock()
		}
		// Record the downloaded data for the stream.
		err = stream.managedRecordDownload(uint64(readData))
		if err != nil {
			errWrite := m.managedWriteErrorFrame(frame.id, err)
			_, errRemove := m.managedRemoveStream(frame.id, err)
			// only log unexpected errors.
			err = errors.Compose(errWrite, errRemove)
			if err != nil {
				m.staticLog.Print("failed to write error frame:", err)
			}
			continue
		}
		// Write payload to stream.
		select {
		case <-stream.staticCtx.Done():
			continue // stream closed
		case <-m.staticCtx.Done():
			return // mux closed
		case stream.staticPayloadChan <- frame.payload:
		}
	}
}
