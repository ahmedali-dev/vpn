package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SOCKS5 Handler

func (v *VPNClient) handleSOCKS5(clientConn net.Conn) {
	defer clientConn.Close()

	select {
	case v.connSemaphore <- struct{}{}:
		defer func() { <-v.connSemaphore }()
	default:
		return
	}

	v.stats.RecordConnection()
	defer v.stats.CloseConnection()

	clientConn.SetDeadline(time.Now().Add(30 * time.Second))

	if err := v.performSOCKS5Handshake(clientConn); err != nil {
		return
	}

	targetAddr, err := v.parseSOCKS5Request(clientConn)
	if err != nil {
		v.sendSOCKS5Reply(clientConn, SOCKS5ReplyGeneralError)
		v.stats.RecordFailure()
		return
	}

	clientConn.SetDeadline(time.Time{})

	var remoteConn net.Conn

	// Use appropriate tunnel based on mode
	if v.config.Mode == ModeSSH {
		remoteConn, err = v.dialThroughSSH(targetAddr)
	} else {
		// For V2Ray/Xray, we're already providing SOCKS5, so this shouldn't be called
		// But we'll handle it gracefully
		err = fmt.Errorf("v2ray/xray mode doesn't use SOCKS5 handler")
	}

	if err != nil {
		v.stats.RecordFailure()
		v.sendSOCKS5Reply(clientConn, SOCKS5ReplyGeneralError)
		return
	}
	defer remoteConn.Close()

	if err := v.sendSOCKS5Reply(clientConn, SOCKS5ReplySuccess); err != nil {
		v.stats.RecordFailure()
		return
	}

	v.stats.RecordSuccess()
	v.forwardDataWithMetrics(clientConn, remoteConn)
}

func (v *VPNClient) performSOCKS5Handshake(conn net.Conn) error {
	buf := make([]byte, 257)

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return fmt.Errorf("handshake read error: %w", err)
	}

	if buf[0] != SOCKS5Version {
		return fmt.Errorf("invalid SOCKS version: %d", buf[0])
	}

	nmethods := int(buf[1])
	if nmethods == 0 {
		return fmt.Errorf("no authentication methods provided")
	}

	if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
		return fmt.Errorf("methods read error: %w", err)
	}

	allowed := false
	for _, method := range buf[:nmethods] {
		if method == 0 {
			allowed = true
		}
	}
	if !allowed {
		_, _ = conn.Write([]byte{SOCKS5Version, 0xff})
		return fmt.Errorf("SOCKS client did not offer no-auth authentication")
	}
	_, err := conn.Write([]byte{SOCKS5Version, 0x00})
	return err
}

func (v *VPNClient) parseSOCKS5Request(conn net.Conn) (string, error) {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", fmt.Errorf("request read error: %w", err)
	}

	if buf[0] != SOCKS5Version || buf[2] != 0 {
		return "", fmt.Errorf("invalid SOCKS request header")
	}
	if buf[1] != SOCKS5CmdConnect {
		v.sendSOCKS5Reply(conn, SOCKS5ReplyCmdNotSupport)
		return "", fmt.Errorf("unsupported command: %d", buf[1])
	}

	addr, err := v.readSOCKS5Address(conn, buf[3])
	if err != nil {
		return "", err
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", fmt.Errorf("port read error: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)

	return net.JoinHostPort(addr, strconv.Itoa(int(port))), nil
}

func (v *VPNClient) readSOCKS5Address(conn net.Conn, atyp byte) (string, error) {
	switch atyp {
	case SOCKS5AtypIPv4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", err
		}
		return net.IP(ip).String(), nil

	case SOCKS5AtypDomain:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return "", err
		}
		domain := make([]byte, length[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}
		return string(domain), nil

	case SOCKS5AtypIPv6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", err
		}
		return net.IP(ip).String(), nil

	default:
		return "", fmt.Errorf("unsupported address type: %d", atyp)
	}
}

func (v *VPNClient) dialThroughSSH(addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(v.ctx, ConnectionTimeout)
	defer cancel()
	v.connPool.dialAttempts.Add(1)
	var lastErr error

	for retry := 0; retry < 3; retry++ {
		client := v.connPool.GetClient()
		if client == nil {
			if retry < 2 {
				if !sleepContext(ctx, 100*time.Millisecond) {
					return nil, ctx.Err()
				}
				continue
			}
			v.connPool.dialErrors.Add(1)
			return nil, fmt.Errorf("SSH client not available")
		}

		conn, err := client.DialContext(ctx, "tcp", addr)
		lastErr = err
		if err == nil {
			v.connPool.MarkHealthy()
			return conn, nil
		}

		if strings.Contains(err.Error(), "connection") || strings.Contains(err.Error(), "closed") {
			v.connPool.MarkUnhealthy()
		}

		if retry < 2 {
			if !sleepContext(ctx, time.Duration(retry+1)*200*time.Millisecond) {
				return nil, ctx.Err()
			}
		}
	}

	v.connPool.dialErrors.Add(1)
	return nil, fmt.Errorf("failed to dial through SSH tunnel: %w", lastErr)
}

func (v *VPNClient) sendSOCKS5Reply(conn net.Conn, replyCode byte) error {
	reply := []byte{SOCKS5Version, replyCode, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	_, err := conn.Write(reply)
	return err
}

func (v *VPNClient) forwardDataWithMetrics(client, remote net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	var bytesIn, bytesOut int64

	go func() {
		defer wg.Done()
		buf := v.bufferPool.Get().([]byte)
		defer v.bufferPool.Put(buf)

		n, _ := v.copyWithBuffer(remote, client, buf)
		bytesOut = n

		if tcp, ok := remote.(interface{ CloseWrite() error }); ok {
			tcp.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		buf := v.bufferPool.Get().([]byte)
		defer v.bufferPool.Put(buf)

		n, _ := v.copyWithBuffer(client, remote, buf)
		bytesIn = n

		if tcp, ok := client.(interface{ CloseWrite() error }); ok {
			tcp.CloseWrite()
		}
	}()

	wg.Wait()
	v.stats.AddBytes(bytesIn, bytesOut)
}

func (v *VPNClient) copyWithBuffer(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	var written int64
	for {
		nr, err := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				return written, ew
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if err != nil {
			if err == io.EOF {
				return written, nil
			}
			return written, err
		}
	}
}
