package mux

import "time"

var (
	// TimeoutNotificationBuffer is the time before the maxTimeout is reached
	// when the mux calls the registered timeout callback method.
	TimeoutNotificationBuffer = 5 * time.Minute // 5 minutes / 25% of the default maxTimeout
)

// updateDeadline handles extending the timeout of the mux's underlying
// connection whenever a frame was read or written.
func (m *Mux) updateDeadline() error {
	// Compute the duration until the next deadline.
	duration := time.Second * time.Duration(m.settings.MaxTimeout)
	// Set the deadline on the connection.
	err := m.staticConn.SetDeadline(time.Now().Add(duration))
	if err != nil {
		return err
	}

	// The deadline for calling the callback should be TimeoutNotificationBuffer
	// before that.
	if duration >= TimeoutNotificationBuffer {
		duration -= TimeoutNotificationBuffer
	} else {
		duration = 0
	}
	m.timeoutCallbackTime = time.Now().Add(duration)

	// Drop a notice that the timeout has changed. Don't block if the buffered
	// channel is already full.
	select {
	case m.staticTimeoutChanged <- struct{}{}:
	default:
	}
	return nil
}

// threadedHandleMaxTimeoutCallback calls the timeout callback of the mux every
// time the mux is about to time out.
func (m *Mux) threadedHandleMaxTimeoutCallback() {
	for {
		// Fetch the timeout deadline.
		m.staticMu.Lock()
		duration := m.timeoutCallbackTime.Sub(time.Now())
		m.staticMu.Unlock()

		// Create a timer and block until it fires. If the timeout is updated
		// before the timer fires, iterate without firing the callback.
		timer := time.NewTimer(duration)
		select {
		case <-m.staticCtx.Done():
			if !timer.Stop() {
				<-timer.C // drain timer
			}
			return
		case <-m.staticTimeoutChanged:
			if !timer.Stop() {
				<-timer.C // drain timer
			}
			continue // timeout changed, don't fire callback
		case <-timer.C:
		}

		// Call the timeout callback in a goroutine to prevent any blocking
		// operations in the callback from preventing this loop from executing
		// or shutting down.
		go m.staticTimeoutCallback(m)

		// Before starting a new timer, wait for the timeout to be updated.
		select {
		case <-m.staticCtx.Done():
			return
		case <-m.staticTimeoutChanged:
		}
	}
}
