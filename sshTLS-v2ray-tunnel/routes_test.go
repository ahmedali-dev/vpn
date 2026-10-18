package main

import "testing"

func TestRouteUsesSelectedTunnelServer(t *testing.T) {
	for _, mode := range []TunnelMode{ModeSSH, ModeV2Ray, ModeXray} {
		client := NewVPNClient(Config{Mode: mode, Host: "192.0.2.1", V2Ray: V2RayConfig{Address: "192.0.2.2"}})
		ip, err := client.resolveServerIP()
		client.cancel()
		if err != nil {
			t.Fatal(err)
		}
		want := "192.0.2.2"
		if mode == ModeSSH {
			want = "192.0.2.1"
		}
		if ip != want {
			t.Fatalf("%s routes to %s, want %s", mode, ip, want)
		}
	}
}

func TestGatewayParsing(t *testing.T) {
	v := &VPNClient{}
	for _, tc := range []struct {
		name, input, want string
		parse             func(string) (string, error)
	}{
		{"linux-ip", "default via 192.0.2.1 dev eth0\n", "192.0.2.1", v.parseLinuxGateway},
		{"linux-route", "0.0.0.0 192.0.2.2 0.0.0.0 UG\n", "192.0.2.2", v.parseLinuxRouteGateway},
		{"macos", "   gateway: 192.0.2.3\n", "192.0.2.3", v.parseDarwinGateway},
		{"windows", "IPv4 Route Table\nActive Routes:\n0.0.0.0 0.0.0.0 192.0.2.4 192.0.2.5 25\n", "192.0.2.4", v.parseWindowsGateway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.parse(tc.input)
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v", got, err)
			}
			if _, err := tc.parse("no gateway"); err == nil {
				t.Fatal("invalid route output accepted")
			}
		})
	}
}
