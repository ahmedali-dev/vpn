package main

import (
	"context"
	"sync"
	"testing"
	"time"
)

type blockedSSH struct {
	once   sync.Once
	closed chan struct{}
}

func (b *blockedSSH) SendRequest(string, bool, []byte) (bool, []byte, error) {
	<-b.closed
	return false, nil, context.Canceled
}
func (b *blockedSSH) Close() error { b.once.Do(func() { close(b.closed) }); return nil }
func TestKeepaliveTimeoutClosesUnresponsivePeer(t *testing.T) {
	b := &blockedSSH{closed: make(chan struct{})}
	start := time.Now()
	if err := boundedKeepalive(context.Background(), b, 20*time.Millisecond); err == nil {
		t.Fatal("unresponsive peer accepted")
	}
	if time.Since(start) > time.Second {
		t.Fatal("keepalive did not bound blocking")
	}
	select {
	case <-b.closed:
	default:
		t.Fatal("peer not closed")
	}
}
