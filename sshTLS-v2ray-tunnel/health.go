package main

import (
	"context"
	"fmt"
	"time"
)

type healthSnapshot struct {
	State     string    `json:"state"`
	LastCheck time.Time `json:"lastCheck"`
	Error     string    `json:"error,omitempty"`
}

func (v *VPNClient) setHealth(state string, err error) {
	v.healthMu.Lock()
	defer v.healthMu.Unlock()
	v.health.State = state
	v.health.LastCheck = time.Now()
	v.health.Error = ""
	if err != nil {
		v.health.Error = err.Error()
	}
}
func (v *VPNClient) getHealth() healthSnapshot {
	v.healthMu.RLock()
	defer v.healthMu.RUnlock()
	return v.health
}
func (v *VPNClient) monitorInternet() {
	defer v.workers.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	failures := 0
	for {
		select {
		case <-v.ctx.Done():
			return
		case <-ticker.C:
			err := v.checkProxyInternet()
			if err == nil && v.config.TUN {
				err = v.checkSystemInternet()
			}
			if v.ctx.Err() != nil {
				return
			}
			if err == nil {
				if failures > 0 {
					v.logln("[+] Internet connectivity recovered.")
				}
				failures = 0
				v.setHealth("healthy", nil)
				continue
			}
			failures++
			v.setHealth("degraded", err)
			v.logf("[!] Connectivity check failed (%d): %v\n", failures, err)
			if failures < 3 {
				continue
			}
			failures = 0
			v.logln("[*] Reconnecting after repeated connectivity failures...")
			if v.config.Mode == ModeSSH {
				err = v.reconnect()
			} else {
				v.reconnectMu.Lock()
				v.v2rayClient.Stop()
				if v.ctx.Err() == nil {
					err = v.v2rayClient.Start(v.config.SOCKSPort)
					if err == nil {
						err = v.verifyRecoveredConnection()
					}
				}
				v.reconnectMu.Unlock()
			}
			if err != nil {
				v.logf("[!] Reconnect failed: %v\n", err)
			}
		}
	}
}

type sshRequestClient interface {
	SendRequest(string, bool, []byte) (bool, []byte, error)
	Close() error
}

func boundedKeepalive(ctx context.Context, client sshRequestClient, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() { _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); done <- err }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		_ = client.Close()
		return ctx.Err()
	case <-timer.C:
		_ = client.Close()
		return fmt.Errorf("SSH keepalive timed out")
	}
}

// Reconnection must establish end-to-end health before clearing degraded status.
func (v *VPNClient) verifyRecoveredConnection() error {
	err := waitForSOCKS(v.ctx, v.config.SOCKSPort)
	if err == nil {
		err = v.checkProxyInternet()
	}
	if err == nil && v.config.TUN {
		err = v.checkSystemInternet()
	}
	if err != nil {
		v.setHealth("degraded", err)
	} else {
		v.setHealth("healthy", nil)
	}
	return err
}
