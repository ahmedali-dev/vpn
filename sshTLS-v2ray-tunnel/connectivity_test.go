package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type connectivityTransport func(*http.Request) (*http.Response, error)

func (f connectivityTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestProxyConnectivityFallbackAndFailures(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: connectivityTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host == "first.example" {
			return nil, errors.New("upstream TLS failed")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok")), Header: make(http.Header)}, nil
	})}
	if err := verifyProxyHTTPS(context.Background(), client, []string{"https://first.example", "https://second.example"}); err != nil || calls != 2 {
		t.Fatalf("fallback failed: %v (%d)", err, calls)
	}
	if err := verifyProxyHTTPS(context.Background(), client, []string{"https://first.example"}); err == nil || !strings.Contains(err.Error(), "upstream TLS failed") {
		t.Fatalf("lost upstream failure: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifyProxyHTTPS(ctx, client, []string{"https://first.example"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost cancellation: %v", err)
	}
}

func TestProxyConnectivityRejectsHTTPFailure(t *testing.T) {
	client := &http.Client{Transport: connectivityTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 502, Body: io.NopCloser(strings.NewReader("bad gateway")), Header: make(http.Header)}, nil
	})}
	if err := verifyProxyHTTPS(context.Background(), client, []string{"https://example.com"}); err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("accepted failed HTTPS check: %v", err)
	}
}
