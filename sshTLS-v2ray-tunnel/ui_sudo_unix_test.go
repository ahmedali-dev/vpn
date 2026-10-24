//go:build !windows

package main

import (
	"strings"
	"testing"
)

func TestUnprivilegedUIUsesDesktopSession(t *testing.T) {
	t.Setenv("DISPLAY", ":0")
	for _, platform := range []string{"darwin", "linux"} {
		program, args := userUICommand(platform, "501", "/Applications/Tunnel App/tunnel", "/tmp/helper", 0)
		joined := strings.Join(args, " ")
		if !strings.Contains(joined, "-u #501 --") || !strings.Contains(joined, "-ui-helper-address-file /tmp/helper") {
			t.Fatal("UI would not run under original user")
		}
		if platform == "darwin" && (program != "/bin/launchctl" || args[0] != "asuser") {
			t.Fatal("missing macOS GUI bootstrap session")
		}
		if platform == "linux" && (!strings.Contains(joined, "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/501/bus") || !strings.Contains(joined, "DISPLAY=:0")) {
			t.Fatal("missing Linux desktop environment")
		}
	}
}
