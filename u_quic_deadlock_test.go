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
