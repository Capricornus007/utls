// Reproduction for the UQUICConn.Close() deadlock: u_quic.go's Close() is missing
// the <-signalc receive that quic.go:268 and crypto/tls both have, so after Start()
// parks the handshake goroutine on an unconditional send to signalc, Close() ranges
// over a blockedc that the goroutine can never reach the close() of.

package tls

import (
	"context"
	"testing"
	"time"
)

func TestUQUICCloseAfterStartDoesNotDeadlock(t *testing.T) {
	config := &QUICConfig{TLSConfig: testConfig.Clone()}
	config.TLSConfig.MinVersion = VersionTLS13

	q := UQUICClient(config, HelloChrome_Auto)
	if err := q.Start(context.Background()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- q.Close() }()

	select {
	case err := <-done:
		t.Logf("Close returned normally (err=%v)", err)
	case <-time.After(5 * time.Second):
		t.Fatal("DEADLOCK: UQUICConn.Close() did not return within 5s after Start(); " +
			"handshake goroutine is parked on quicWaitForSignal's signalc send")
	}
}

// TestUQUICNextEventReportsHandshakeError locks in the crypto/tls behaviour that
// UQUICConn.NextEvent used to be missing: a failed handshake must surface as a
// QUICErrorEvent carrying the error. Without it, a QUIC consumer can only observe
// its own deadline, so a TLS-level rejection is indistinguishable from a timeout.
// quic-go's utlsQUICConn event switch has to handle the kind in lockstep, or the
// new event panics the process.
func TestUQUICNextEventReportsHandshakeError(t *testing.T) {
	config := &QUICConfig{TLSConfig: testConfig.Clone()}
	config.TLSConfig.MinVersion = VersionTLS13

	q := UQUICClient(config, HelloChrome_Auto)
	if err := q.Start(context.Background()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// HandleData can park on the handshake goroutine, so drive it from the side.
	go func() {
		// A record header claiming an impossible length makes the stack fail the
		// handshake instead of waiting forever for more data.
		_ = q.HandleData(QUICEncryptionLevelInitial, []byte{0x16, 0x03, 0x03, 0xff, 0xff})
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ev := q.NextEvent()
		switch ev.Kind {
		case QUICErrorEvent:
			if ev.Err == nil {
				t.Fatal("QUICErrorEvent carried a nil Err")
			}
			return
		case QUICNoEvent:
			time.Sleep(10 * time.Millisecond)
		}
	}
	t.Fatal("no QUICErrorEvent within 5s: NextEvent is not surfacing handshakeErr")
}
