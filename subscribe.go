package uplomux

// This file contains code relevant to the two handshakes executed by the
// UploMux.
// 1. AppSeed handshake
// This handshake happens right after a mux.Mux is created. The first stream
// that is created using the new mux will send the own appSeed and the receiver
// will return its own appSeed. Those two are added together to form a unique
// seed which can be used to deduplicate connections between the same
// applications.
// 2. Subscriber handshake
// The subscriber handshake happens every time a new stream is created. When
// creating a stream the user sends a subscriber name to subscribe to a
// listener. Upon success the listening UploMux will return a response with an
// empty string and otherwise an error message if the specified listener doesn't
// exist.

import (
	"bytes"
	"io"

	"github.com/uplo-tech/encoding"
	"github.com/uplo-tech/errors"
)

var errUnknownSubscriber = errors.New("unknown subscriber")

const (
	encodingMaxLen = 4096
)

type (
	// appSeed is a random number, which is not persisted, to uniquely identify an
	// application using a UploMux in case multiple muxes run on the same
	// machine.
	appSeed uint64
	// subscriberRequest is the request sent at the beginning of every new
	// stream to let the other UploMux know which listener the sender wants to
	// subscribe to.
	subscriberRequest struct {
		Subscriber string
	}
	// subscriberResponse is the response of the receiver to receiving a
	// subscriberRequest. It will return an empty string if subscribing was
	// successful and an error otherwise.
	subscriberResponse struct {
		Err string
	}
	// seedRequest is the request sent by the UploMux upon connecting to another
	// UploMux. After setting up the mux.Mux a stream is created to send the
	// request, receive the response and then closed.
	seedRequest struct {
		AppSeed appSeed
	}
	// seedResponse is the response sent by the UploMux upon being connected to
	// by another UploMux. After setting up the mux.Mux a stream is created to
	// send the request, receive the response and then closed.
	seedResponse struct {
		AppSeed appSeed
	}
)

// writeObjectAtomically writes an object to a memory buffer first and then
// writes the buffer to the provided io.Writer with a single call to Write.
func writeObjectAtomically(w io.Writer, v interface{}) error {
	buf := new(bytes.Buffer)
	err := encoding.WriteObject(buf, v)
	if err != nil {
		return errors.New("writeObjectAtomically: failed to encode object")
	}
	_, err = buf.WriteTo(w)
	return err
}

// writeSubscriberRequest writes the subscriberRequest object to the writer.
func writeSubscriberRequest(w io.Writer, subscriber string) error {
	return writeObjectAtomically(w, subscriberRequest{subscriber})
}

// writeSubscriberResponse writes the subscriberResponse object to the writer.
func writeSubscriberResponse(w io.Writer, err error) error {
	var errStr string
	if err != nil {
		errStr = err.Error()
	}
	return writeObjectAtomically(w, subscriberResponse{
		Err: errStr,
	})
}

// readSubscriber reads a `subscriberRequest` from the stream and returns the
// `Subscriber` field from it.
func readSubscriber(stream Stream) (string, error) {
	var sr subscriberRequest
	if err := encoding.ReadObject(stream, &sr, encodingMaxLen); err != nil {
		return "", errors.AddContext(err, "readSubscriber: failed to ReadObject")
	}
	return sr.Subscriber, nil
}

// readSubscriberResponse reads the response from the stream and returns two
// errors. The first one is the error returned on the stream, i.e. if the remote
// party responded with an error. The second one represents an error that
// occurred while trying to read from the stream, i.e. bad stream communication.
// If both errors are nil then the communication was successful.
func readSubscriberResponse(stream Stream) (error, error) {
	var sr subscriberResponse
	if err := encoding.ReadObject(stream, &sr, encodingMaxLen); err != nil {
		return nil, errors.AddContext(err, "readSubscriberResponse: failed to ReadObject")
	}
	if sr.Err != "" {
		return errors.New(sr.Err), nil
	}
	return nil, nil
}

func writeSeedRequest(stream Stream, appSeed appSeed) error {
	return writeObjectAtomically(stream, seedRequest{
		AppSeed: appSeed,
	})
}

func writeSeedResponse(stream Stream, appSeed appSeed) error {
	return writeObjectAtomically(stream, seedResponse{
		AppSeed: appSeed,
	})
}

func readSeedRequest(stream Stream) (appSeed, error) {
	var sr seedRequest
	if err := encoding.ReadObject(stream, &sr, encodingMaxLen); err != nil {
		return 0, errors.AddContext(err, "readSeedRequest: failed to ReadObject")
	}
	return sr.AppSeed, nil
}

func readSeedResponse(stream Stream) (appSeed, error) {
	var sr seedResponse
	if err := encoding.ReadObject(stream, &sr, encodingMaxLen); err != nil {
		return 0, errors.AddContext(err, "readSeedResponse: failed to ReadObject")
	}
	return sr.AppSeed, nil
}
