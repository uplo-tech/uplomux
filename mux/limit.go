package mux

import (
	"sync"

	"github.com/uplo-tech/errors"
)

// BandwidthLimit is an interface that can be implemented to limit the amount of
// outgoing or incoming bandwidth.
type BandwidthLimit interface {
	// Downloaded returns how many bytes have been received by the stream. This
	// is usually called by the caller which implements the interface.
	Downloaded() uint64
	// Uploaded returns how many bytes have been written to the stream. This is
	// usually called by the caller which implements the interface.
	Uploaded() uint64
	// RecordDownload records a download and is called by the mux after reading
	// a frame from the connection.
	RecordDownload(bytes uint64) error
	// RecordUpload records an upload and is called by the mux after writing a
	// frame to the connection.
	RecordUpload(bytes uint64) error
}

// NoLimit implements the BandwidthLimiter without a limit. This is the default
// limiter for every stream.
type NoLimit struct {
	downloaded uint64
	uploaded   uint64
	mu         sync.Mutex
}

// Downloaded implements the BandwidthLimit interface.
func (nl *NoLimit) Downloaded() uint64 {
	nl.mu.Lock()
	defer nl.mu.Unlock()
	return nl.downloaded
}

// Uploaded implements the BandwidthLimit interface.
func (nl *NoLimit) Uploaded() uint64 {
	nl.mu.Lock()
	defer nl.mu.Unlock()
	return nl.uploaded
}

// RecordDownload implements the BandwidthLimit interface.
func (nl *NoLimit) RecordDownload(bytes uint64) error {
	nl.mu.Lock()
	defer nl.mu.Unlock()
	nl.downloaded += bytes
	return nil
}

// RecordUpload implements the BandwidthLimit interface.
func (nl *NoLimit) RecordUpload(bytes uint64) error {
	nl.mu.Lock()
	defer nl.mu.Unlock()
	nl.uploaded += bytes
	return nil
}

// SetLimit sets a custom limit on the stream and initiates it to continue from
// where the last limit left off.
func (s *Stream) SetLimit(limit BandwidthLimit) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Start the new limit from where the old one left off.
	errDown := limit.RecordDownload(s.bandwidthLimit.Downloaded())
	errUp := limit.RecordUpload(s.bandwidthLimit.Uploaded())
	if err := errors.Compose(errDown, errUp); err != nil {
		return err
	}
	// Swap out limits.
	s.bandwidthLimit = limit
	return nil
}
