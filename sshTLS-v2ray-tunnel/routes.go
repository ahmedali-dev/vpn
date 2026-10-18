package main

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

var errRouteExists = errors.New("server route already exists")

func (v *VPNClient) setupRoutes() error {
	rm := v.routeManager
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.routeAdded.Load() {
		return nil
	}

	fmt.Println("[*] Setting up automatic routing...")
	fmt.Printf("[*] Platform: %s\n", runtime.GOOS)

	if !isAdmin() {
		return fmt.Errorf("insufficient privileges - run as Administrator/root")
	}
	fmt.Println("[+] Running with elevated privileges")

	serverIP, err := v.resolveServerIP()
	if err != nil {
		return fmt.Errorf("failed to resolve server IP: %w", err)
	}
	rm.serverIP = serverIP
	fmt.Printf("[+] Server IP: %s\n", serverIP)

	gateway, err := v.getDefaultGateway()
	if err != nil {
		return fmt.Errorf("failed to get default gateway: %w", err)
	}
	rm.originalGateway = gateway
	fmt.Printf("[+] Original gateway: %s\n", gateway)

	fmt.Printf("[*] Adding route: %s via %s\n", serverIP, gateway)
	if err := v.addServerRoute(serverIP, gateway); err != nil {
		if errors.Is(err, errRouteExists) {
			fmt.Println("[*] Existing server route retained; it will not be removed on shutdown")
			return nil
		}
		return fmt.Errorf("failed to add server route: %w", err)
	}

	time.Sleep(time.Second)
	exists, _ := v.checkServerRoute(serverIP)
	if exists {
		fmt.Println("[+] Route verified successfully!")
		rm.routeAdded.Store(true)
		return nil
	}

	fmt.Println("[!] Warning: Route added but verification failed")
	rm.routeAdded.Store(true)
	return nil
}

func (v *VPNClient) cleanupRoutes() error {
	rm := v.routeManager
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if !rm.routeAdded.Load() {
		return nil
	}

	fmt.Println("[*] Cleaning up routes...")
	if err := v.deleteServerRoute(rm.serverIP); err != nil {
		fmt.Printf("[!] Failed to remove server route: %v\n", err)
	}

	rm.routeAdded.Store(false)
	fmt.Println("[+] Routes cleaned up")
	return nil
}

func (v *VPNClient) monitorRoutes() {
	ticker := time.NewTicker(RouteCheckInterval)
	defer ticker.Stop()

	for v.running.Load() {
		select {
		case <-ticker.C:
			if v.routeManager.routeAdded.Load() {
				exists, _ := v.checkServerRoute(v.routeManager.serverIP)
				if !exists {
					fmt.Println("\n[!] Route lost, restoring...")
					v.routeManager.routeAdded.Store(false)
					if err := v.setupRoutes(); err != nil {
						fmt.Printf("[!] Failed to restore routes: %v\n", err)
					} else {
						fmt.Println("[+] Routes restored")
					}
				}
			}
		case <-v.ctx.Done():
			return
		}
	}
}

func (v *VPNClient) resolveServerIP() (string, error) {
	host := v.config.Host
	if v.config.Mode == ModeV2Ray || v.config.Mode == ModeXray {
		host = v.config.V2Ray.Address
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return "", fmt.Errorf("server host routes currently require IPv4")
		}
		return host, nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}

	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}

	return "", fmt.Errorf("server host routes currently require IPv4")
}

func (v *VPNClient) getDefaultGateway() (string, error) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("ip", "route", "show", "default")
		output, err := cmd.CombinedOutput()
		if err == nil {
			return v.parseLinuxGateway(string(output))
		}
		cmd = exec.Command("route", "-n")
		output, err = cmd.CombinedOutput()
		if err != nil {
			return "", err
		}
		return v.parseLinuxRouteGateway(string(output))

	case "darwin":
		cmd = exec.Command("route", "-n", "get", "default")

	case "windows":
		cmd = exec.Command("route", "PRINT", "0.0.0.0")

	default:
		return "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	switch runtime.GOOS {
	case "darwin":
		return v.parseDarwinGateway(string(output))
	case "windows":
		return v.parseWindowsGateway(string(output))
	}

	return "", fmt.Errorf("unsupported OS")
}

func (v *VPNClient) parseLinuxGateway(output string) (string, error) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "default") && strings.Contains(line, "via") {
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "via" && i+1 < len(fields) {
					if net.ParseIP(fields[i+1]) != nil {
						return fields[i+1], nil
					}
				}
			}
		}
	}
	return "", fmt.Errorf("gateway not found")
}

func (v *VPNClient) parseLinuxRouteGateway(output string) (string, error) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "0.0.0.0" {
			if net.ParseIP(fields[1]) != nil {
				return fields[1], nil
			}
		}
	}
	return "", fmt.Errorf("gateway not found")
}

func (v *VPNClient) parseDarwinGateway(output string) (string, error) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "gateway:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && net.ParseIP(fields[1]) != nil {
				return fields[1], nil
			}
		}
	}
	return "", fmt.Errorf("gateway not found")
}

func (v *VPNClient) parseWindowsGateway(output string) (string, error) {
	lines := strings.Split(output, "\n")
	inRouteTable := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "IPv4 Route Table") || strings.Contains(line, "Active Routes:") {
			inRouteTable = true
			continue
		}
		if !inRouteTable || strings.Contains(line, "Persistent Routes:") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			if net.ParseIP(fields[2]) != nil && fields[2] != "0.0.0.0" {
				return fields[2], nil
			}
		}
	}
	return "", fmt.Errorf("gateway not found")
}

func (v *VPNClient) addServerRoute(serverIP, gateway string) error {
	cmd := v.getAddRouteCommand(serverIP, gateway)
	if cmd == nil {
		return fmt.Errorf("unsupported platform")
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		lowerOutput := strings.ToLower(string(output))
		if strings.Contains(lowerOutput, "exist") || strings.Contains(lowerOutput, "already") {
			return errRouteExists
		}
		return err
	}
	return nil
}

func (v *VPNClient) deleteServerRoute(serverIP string) error {
	cmd := v.getDeleteRouteCommand(serverIP)
	if cmd == nil {
		return nil
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		lowerOutput := strings.ToLower(string(output))
		if strings.Contains(lowerOutput, "not found") || strings.Contains(lowerOutput, "no such") {
			return nil
		}
	}
	return err
}

func (v *VPNClient) checkServerRoute(serverIP string) (bool, error) {
	cmd := v.getCheckRouteCommand(serverIP)
	if cmd == nil {
		return false, nil
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, nil
	}

	return strings.Contains(string(output), serverIP), nil
}

func (v *VPNClient) getAddRouteCommand(serverIP, gateway string) *exec.Cmd {
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("ip"); err == nil {
			return exec.Command("ip", "route", "add", serverIP+"/32", "via", gateway)
		}
		return exec.Command("route", "add", "-host", serverIP, "gw", gateway)
	case "darwin":
		return exec.Command("route", "-n", "add", "-host", serverIP, gateway)
	case "windows":
		return exec.Command("route", "ADD", serverIP, "MASK", "255.255.255.255", gateway, "METRIC", "1")
	}
	return nil
}

func (v *VPNClient) getDeleteRouteCommand(serverIP string) *exec.Cmd {
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("ip"); err == nil {
			return exec.Command("ip", "route", "del", serverIP)
		}
		return exec.Command("route", "del", "-host", serverIP)
	case "darwin":
		return exec.Command("route", "-n", "delete", "-host", serverIP)
	case "windows":
		return exec.Command("route", "DELETE", serverIP)
	}
	return nil
}

func (v *VPNClient) getCheckRouteCommand(serverIP string) *exec.Cmd {
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("ip"); err == nil {
			return exec.Command("ip", "route", "get", serverIP)
		}
		return exec.Command("route", "-n", "get", serverIP)
	case "darwin":
		return exec.Command("route", "-n", "get", serverIP)
	case "windows":
		return exec.Command("route", "PRINT")
	}
	return nil
}
