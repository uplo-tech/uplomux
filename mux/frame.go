package mux

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/uplo-tech/encoding"
	"github.com/uplo-tech/errors"
	"github.com/uplo-tech/uplomux/build"
)

// TODO (followup): extend writeFrame and readFrame to support covert frames.

var (
	// ErrPayloadTooBig is returned when the payload can't fit within the given
	// maximum number of packets per frame.
	ErrPayloadTooBig = errors.New("maxEncryptedFrameSizePackets too small for payload")

	// ErrPayloadTooSmall is returned when the payload is too small to kill the
	// given minimum number of packets per frame.
	ErrPayloadTooSmall = errors.New("payload doesn't fill the minEncryptedFrameSizePackets")
)

const (
	// marshaledHeaderSize returns the number of bytes it takes to marshal a frame
	// without its payload. This is the same size for every frame.
	marshaledFrameHeaderSize = 4 + 4 + 2
	// marshaledEstablishEncryptionRequestFrameSize is the number of bytes that
	// a frame with an establishEncryptionRequest in the payload has.
	marshaledEstablishEncryptionRequestFrameSize = marshaledFrameHeaderSize + 56
	// marshaledEstablishEncryptionResponseFrameSize is the number of bytes that
	// a frame with an establishEncryptionResponse in the payload has.
	marshaledEstablishEncryptionResponseFrameSize = marshaledFrameHeaderSize + 112
)

// Flag bits and what they mean.
const (
	// frameBitFinalFrame indicates whether or not this is the final frame for
	// this stream. If set, the stream is expected to be closed with no
	// response.
	frameBitFinalFrame = 1 << 0
	// frameBitErrorFrame indicates whether the stream is being closed because
	// of a UploMux error. If set, the entire payload is an error string. Bit 0
	// must be set if bit 1 is set.
	frameBitErrorFrame = 1 << 1
	// frameBitPaddingContainsAnotherFrame indicates that another frame exists
	// in the padding of the current frame. This is an optimization technique to
	// increase the frame density when every frame needs to be padded to an
	// exact number of packets.
	frameBitPaddingContainsAnotherFrame = 1 << 2
)

// The first 256 reserved IDs and their meanings.
const (
	// frameIDErrorBadInit indicates that the frame ID was initialized
	// improperly, using the empty value instead of setting the frame to a
	// correct value. Any time the uplomux receives a frameErrorBadInit, an
	// error frame will be returned to the peer indicating that a bad frame was
	// sent.
	frameIDErrorBadInit = iota
	// frameIDEstablishEncryption is used to indicate that a frame contains
	// setup information to establish a connection between two UploMux peers. If
	// setup has not yet been completed, this is the only frame ID that is
	// allowed.
	frameIDEstablishEncryption
	// frameIDUpdateSettings is used to indicate that a peer wants to update
	// their connection settings. This is the first frame that is sent after
	// establishing an encrypted connection.
	frameIDUpdateSettings
	// frameIDKeepalive indicates that the peer is sending this frame to reset
	// the timeout on the UploMux connection. Keepalive frames only need to be
	// sent if there has been no other recent activity - all frames will reset
	// the keepalive.
	frameIDKeepalive
	// frameIDNewStream announces the creation of a new stream from the other
	// party. This frame is used to create new multiplexed connections across
	// the UploMux and will not only contain the announcement of a new stream but
	// also the first bits of data in the stream.
	frameIDNewStream
)

// frame defines a single frame for sending data through the uplomux session.
// Each frame has 10 bytes of overhead plus the potential AEAD overhead after
// encryption. Typically, this will result in substantially less than 1%
// overhead for high performance transfers.
type frame struct {
	frameHeader

	// The payload that is intended to be forwarded to the underlying stream.
	payload []byte
}

// frameHeader is the constant size header portion of a frame.
type frameHeader struct {
	// The id of the frame indicates what stream the frame is contributing to. A
	// set of reserved IDs are used for UploMux communications.
	id uint32

	// length indicates the number of bytes in the payload of the frame. All
	// frames are padded so that they consume an exact number of packets.
	length uint32

	// flags describes 16 flags that can be set to indicate information about
	// the frame and optimizations within the frame.
	flags uint16
}

// Marshal marshals a frame into a byte slice. This is equal to calling Marshal
// on the header and appending the payload.
func (f frame) Marshal() ([]byte, error) {
	header, err := f.frameHeader.Marshal()
	if err != nil {
		return nil, errors.AddContext(err, "failed to marshal header")
	}
	return append(header, f.payload...), nil
}

// Unmarshal unmarshals a frame.
func (f *frame) Unmarshal(d []byte) error {
	var fh frameHeader
	err := fh.Unmarshal(d)
	if err != nil {
		return errors.AddContext(err, "failed to unmarshal header")
	}
	if uint32(len(d[marshaledFrameHeaderSize:])) < fh.length {
		return errors.New("failed to unmarshal frame due to not enough data being available")
	}
	*f = frame{
		frameHeader: fh,
		payload:     d[marshaledFrameHeaderSize:][:fh.length],
	}
	return nil
}

// Marshal marshals a frame header into a byte slice.
func (fh frameHeader) Marshal() ([]byte, error) {
	d := make([]byte, marshaledFrameHeaderSize)
	binary.LittleEndian.PutUint32(d[:4], fh.id)
	binary.LittleEndian.PutUint32(d[4:8], fh.length)
	binary.LittleEndian.PutUint16(d[8:10], fh.flags)
	return d, nil
}

// Unmarshal unmarshals a byte slice into a frameHeader.
func (fh *frameHeader) Unmarshal(d []byte) error {
	if len(d) < marshaledFrameHeaderSize {
		return errors.New("failed to unmarshal frame header due to not enough data being available")
	}
	fh.id = binary.LittleEndian.Uint32(d[:4])
	fh.length = binary.LittleEndian.Uint32(d[4:8])
	fh.flags = binary.LittleEndian.Uint16(d[8:10])
	return nil
}

// writeFrame encrypts a frame, adds padding if necessary and finally writes it
// to the provided io.Writer. It will write to the provided writer using a
// single call to `w.Write` to guarantee that the write is atomic. That way,
// either the full frame is sent or an error is returned.
func writeFrame(w io.Writer, aead cipher.AEAD, f frame, minEncryptedFrameSizePackets, maxEncryptedFrameSizePackets, packetSize uint32) (int, error) {
	// Sanity check inputs.
	if minEncryptedFrameSizePackets > maxEncryptedFrameSizePackets {
		err := fmt.Errorf("minEncryptedFrameSize > maxEncryptedFrameSize: %v > %v", minEncryptedFrameSizePackets, maxEncryptedFrameSizePackets)
		build.Critical(err)
		return 0, err
	}
	if maxFramePayloadSize(maxEncryptedFrameSizePackets*packetSize, aead) < len(f.payload) {
		build.Critical(ErrPayloadTooBig)
		return 0, ErrPayloadTooBig
	}
	// Figure out minimum frame size to use.
	requiredPackets, _ := requiredPackets(f.length, packetSize, aead)
	encryptedFrameSize := requiredPackets * packetSize
	// Sanity check the requiredPackets.
	if requiredPackets > maxEncryptedFrameSizePackets {
		build.Critical(ErrPayloadTooBig)
		return 0, ErrPayloadTooBig
	}
	if requiredPackets < minEncryptedFrameSizePackets {
		build.Critical(ErrPayloadTooSmall)
		return 0, ErrPayloadTooSmall
	}
	serializedFrame, err := serializeFrame(f, aead, encryptedFrameSize)
	if err != nil {
		return 0, errors.AddContext(err, "failed to serialize frame")
	}
	// Write them.
	return w.Write(serializedFrame)
}

// serializeFrame marshals and encrypts the frame's header and payload. The
// `size` param is the length to which the frame's size should be padded.
func serializeFrame(f frame, aead cipher.AEAD, encryptedFrameSize uint32) ([]byte, error) {
	// Marshal the header.
	headerBytes, err := f.frameHeader.Marshal()
	if err != nil {
		return nil, errors.AddContext(err, "failed to marshal header")
	}
	// Encrypt header and payload.
	encryptedHeader, err := encryptFrameHeader(headerBytes, aead)
	if err != nil {
		return nil, errors.AddContext(err, "failed to encrypt header")
	}
	encryptedPayload, err := encryptFramePayload(f.payload, encryptedFrameSize, aead)
	if err != nil {
		return nil, errors.AddContext(err, "failed to encrypt payload")
	}
	frameBytes := append(encryptedHeader, encryptedPayload...)
	// Sanity check - the frame should be exactly encryptedFrameSize bytes.
	if len(frameBytes) != int(encryptedFrameSize) {
		build.Critical(fmt.Sprintf("expected the serialized frame to be %v bytes but was %v", encryptedFrameSize, len(frameBytes)))
	}
	return frameBytes, nil
}

// readFrame reads a frame from the provided io.Reader, decrypts it and finally
// unmarshals it. It returns the number of read bytes, the frame and any unused
// payload (which might contain a packed frame).
func readFrame(r io.Reader, aead cipher.AEAD, maxEncryptedFrameSize, packetSize uint32) (int, frame, []byte, error) {
	// Read header.
	headerSize := encryptedHeaderSize(aead)
	encryptedHeader := make([]byte, headerSize)
	n1, err := io.ReadFull(r, encryptedHeader)
	if err, ok := err.(net.Error); ok && err.Timeout() {
		return 0, frame{}, []byte{}, err // don't wrap timeout error
	}
	if err != nil {
		return 0, frame{}, []byte{}, errors.AddContext(err, "failed to read encrypted header")
	}
	// Decrypt header.
	header, err := decryptFrameHeader(encryptedHeader, aead)
	if err != nil {
		return 0, frame{}, []byte{}, errors.AddContext(err, "failed to decrypt frame header")
	}
	// Unmarshal header.
	var fh frameHeader
	if err := fh.Unmarshal(header); err != nil {
		return 0, frame{}, []byte{}, errors.AddContext(err, "failed to unmarshal frame header")
	}
	// Check payload length.
	maxPayloadSize := maxFramePayloadSize(maxEncryptedFrameSize, aead)
	if fh.length > uint32(maxPayloadSize) {
		return 0, frame{}, []byte{}, fmt.Errorf("frame payload is too large %v > %v", fh.length, maxPayloadSize)
	}
	// Compute encrypted payload length. We expect the amount of padding after
	// the payload to be < packetSize.
	encryptionOverhead := aead.Overhead() + aead.NonceSize()
	encryptedPayloadSize := fh.length + uint32(encryptionOverhead)
	if mod := (encryptedPayloadSize + uint32(n1)) % packetSize; mod != 0 {
		encryptedPayloadSize += (packetSize - mod)
	}
	// Read payload.
	encryptedPayload := make([]byte, encryptedPayloadSize)
	n2, err := io.ReadFull(r, encryptedPayload)
	if err, ok := err.(net.Error); ok && err.Timeout() {
		return 0, frame{}, []byte{}, err // don't wrap timeout error
	}
	if err != nil {
		return 0, frame{}, []byte{}, errors.AddContext(err, "failed to read encrypted payload")
	}
	// Decrypt the payload.
	payload, err := decryptFramePayload(encryptedPayload, aead)
	if err != nil {
		return 0, frame{}, []byte{}, errors.AddContext(err, "failed to decrypt payload")
	}
	f := frame{
		frameHeader: fh,
		payload:     payload[:fh.length],
	}
	return n1 + n2, f, payload[fh.length:], nil
}

// newEstablishEncryptionRequestFrame creates a new frame that can be sent over
// the wire to establish an encrypted stream. It generates a new ephemeral key
// pair every time it is called.
func newEstablishEncryptionRequestFrame() (X25519SecretKey, X25519PublicKey, frame) {
	// Prepare request.
	xsk, xpk := generateX25519KeyPair()
	req := establishEncryptionRequest{
		Ciphers:   []CipherSpecifier{CipherSpecifierChaCha20Poly1305},
		PublicKey: xpk,
	}
	// Prepare frame.
	payload := encoding.Marshal(req)
	f := frame{
		frameHeader: frameHeader{
			id:     frameIDEstablishEncryption,
			length: uint32(len(payload)),
			flags:  0,
		},
		payload: payload,
	}
	return xsk, xpk, f
}

// newEstablishEncryptionResponseFrame creates a new frame that can be sent over
// the wire to establish an encrypted stream. It generates a new ephemeral key
// pair every time it is called.
func newEstablishEncryptionResponseFrame(requestPubKey X25519PublicKey, serverPrivKey ED25519SecretKey) (X25519SecretKey, CipherSpecifier, frame) {
	// Create signature.
	xsk, xpk := generateX25519KeyPair()
	hash := createSignatureHash(xpk, requestPubKey)
	sig := signHash(hash, serverPrivKey)
	// Prepare response.
	resp := establishEncryptionResponse{
		Cipher:    CipherSpecifierChaCha20Poly1305,
		PublicKey: xpk,
		Signature: sig,
	}
	// Prepare frame.
	payload := encoding.Marshal(resp)
	f := frame{
		frameHeader: frameHeader{
			id:     frameIDEstablishEncryption,
			length: uint32(len(payload)),
			flags:  0,
		},
		payload: payload,
	}
	return xsk, resp.Cipher, f
}

// newUpdateConnectionSettingsFrame creates a new frame containing updated
// connection settings.
func newUpdateConnectionSettingsFrame(settings connectionSettings) frame {
	// Prepare frame.
	payload := encoding.Marshal(settings)
	f := frame{
		frameHeader: frameHeader{
			id:     frameIDUpdateSettings,
			length: uint32(len(payload)),
			flags:  0,
		},
		payload: payload,
	}
	return f
}

// newPayloadFrame creates a new frame with the given stream id and payload.
func newPayloadFrame(id uint32, payload []byte) frame {
	return frame{
		frameHeader: frameHeader{
			id:     id,
			length: uint32(len(payload)),
			flags:  0,
		},
		payload: payload,
	}
}

// newErrorFrame creates a new frame with the given stream id and the given
// error as payload.
func newErrorFrame(id uint32, err error) frame {
	f := newPayloadFrame(id, []byte(err.Error()))
	f.flags = frameBitErrorFrame | frameBitFinalFrame
	return f
}

// newKeepaliveFrame is an empty payload frame with the frameIDKeepalive ID.
func newKeepaliveFrame() frame {
	f := newPayloadFrame(frameIDKeepalive, []byte{})
	return f
}

// newFinalFrame creates a new frame with the given stream id and the correct
// flags set.
func newFinalFrame(id uint32) frame {
	f := newPayloadFrame(id, nil)
	f.flags = frameBitFinalFrame
	return f
}
