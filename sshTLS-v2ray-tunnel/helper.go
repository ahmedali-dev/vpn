package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const helperLeaseTimeout = 35 * time.Second

type helperClient struct {
	address *url.URL
	client  *http.Client
	cancel  context.CancelFunc
	once    sync.Once
}

func newHelperClient(raw string) (*helperClient, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.Path != "/" || u.RawQuery != "" || u.User != nil || len(u.Fragment) != 64 || strings.Trim(u.Fragment, "0123456789abcdef") != "" {
		return nil, fmt.Errorf("invalid privileged helper address")
	}
	return &helperClient{address: u, client: &http.Client{Timeout: 25 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (h *helperClient) request(ctx context.Context, path string, body interface{}) (map[string]interface{}, error) {
	var data []byte
	var err error
	method := http.MethodGet
	if body != nil {
		method = http.MethodPost
		data, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}
	u := h.address.ResolveReference(&url.URL{Path: path})
	u.Fragment = ""
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Tunnel-Token", h.address.Fragment)
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("privileged helper unavailable")
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 128*1024)).Decode(&result); err != nil {
		return nil, fmt.Errorf("invalid helper response")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("helper: %v", result["error"])
	}
	return result, nil
}
func (h *helperClient) close() {
	h.once.Do(func() {
		if h.cancel != nil {
			h.cancel()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = h.request(ctx, "/api/quit", map[string]bool{})
	})
}
func (m *controlManager) getHelper() *helperClient {
	m.helperMu.Lock()
	defer m.helperMu.Unlock()
	return m.helper
}
func (m *controlManager) attachHelper(raw string) error {
	h, err := newHelperClient(raw)
	if err != nil {
		return err
	}
	if _, err = h.request(context.Background(), "/api/lease", map[string]bool{}); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	m.helperMu.Lock()
	old := m.helper
	m.helper = h
	m.helperMu.Unlock()
	if old != nil {
		old.close()
	}
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := h.request(ctx, "/api/lease", map[string]bool{}); err != nil {
					return
				}
			}
		}
	}()
	return nil
}
func (m *controlManager) detachHelper() {
	m.helperMu.Lock()
	h := m.helper
	m.helper = nil
	m.helperMu.Unlock()
	if h != nil {
		h.close()
	}
}
func watchHelperLease(ctx context.Context, cancel context.CancelFunc, last *atomic.Int64) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if time.Since(time.Unix(0, last.Load())) > helperLeaseTimeout {
				cancel()
				return
			}
		}
	}
}
