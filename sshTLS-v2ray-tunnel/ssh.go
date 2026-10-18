package main

import (
	"context"
	"fmt"
	"golang.org/x/crypto/ssh"
	"net"
	"strconv"
	"time"
)

// SSH Tunnel Methods (existing code)

func (v *VPNClient) createTLSConnection() (net.Conn, error) { return v.dialSSHTransport() }

func (v *VPNClient) connectSSH() error {
	var lastErr error
	for attempt := 0; attempt < MaxRetries; attempt++ {
		if err := v.attemptSSHConnection(); err != nil {
			lastErr = err
			if attempt < MaxRetries-1 {
				v.logf("[!] Attempt %d/%d failed: %v\n", attempt+1, MaxRetries, err)
				backoff := RetryDelay * time.Duration(attempt+1)
				v.logf("[*] Retrying in %v...\n", backoff)
				if !sleepContext(v.ctx, backoff) {
					return v.ctx.Err()
				}
				continue
			}
		} else {
			return nil
		}
	}
	return fmt.Errorf("failed after %d attempts: %w", MaxRetries, lastErr)
}

func (v *VPNClient) attemptSSHConnection() error {
	callback, err := v.sshHostKeyCallback()
	if err != nil {
		return err
	}
	tlsConn, err := v.createTLSConnection()
	if err != nil {
		return err
	}

	v.logf("[*] Authenticating as %s...\n", v.config.Username)

	config := &ssh.ClientConfig{
		User: v.config.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(v.config.Password),
		},
		HostKeyCallback: callback,
		Timeout:         ConnectionTimeout,
	}

	tlsConn.SetDeadline(time.Now().Add(ConnectionTimeout))
	stop := context.AfterFunc(v.ctx, func() { tlsConn.Close() })
	defer stop()
	sshConn, chans, reqs, err := ssh.NewClientConn(tlsConn, net.JoinHostPort(v.config.Host, strconv.Itoa(v.config.Port)), config)
	if err != nil {
		tlsConn.Close()
		return fmt.Errorf("SSH connection failed: %w", err)
	}

	tlsConn.SetDeadline(time.Time{})
	if v.ctx.Err() != nil {
		tlsConn.Close()
		return v.ctx.Err()
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	v.connPool.SetClient(client)
	v.logln("[+] SSH authentication successful!")
	return nil
}
