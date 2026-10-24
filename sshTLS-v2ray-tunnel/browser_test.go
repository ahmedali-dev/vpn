package main

import (
	"testing"
)

func TestControlBrowserPreservesSessionURL(t *testing.T) {
	address := "http://127.0.0.1:54321/#0123456789abcdef"
	for platform, want := range map[string]string{"darwin": "open", "linux": "xdg-open", "windows": "rundll32.exe"} {
		t.Run(platform, func(t *testing.T) {
			program, args, err := controlBrowserCommand(platform, address)
			if err != nil || program != want || len(args) == 0 || args[len(args)-1] != address {
				t.Fatalf("session URL was lost: %q %q (%v)", program, args, err)
			}
			if platform == "windows" && (len(args) != 2 || args[0] != "url.dll,FileProtocolHandler") {
				t.Fatal("Windows browser handler is missing")
			}
		})
	}
	if _, _, err := controlBrowserCommand("unsupported", address); err == nil {
		t.Fatal("unsupported platform should return an error")
	}
}

func TestHeadlessUIFlag(t *testing.T) {
	for _, noBrowser := range []bool{false, true} {
		args := []string{"-ui"}
		if noBrowser {
			args = append(args, "-ui-no-browser")
		}
		cfg, err := parseConfig(args)
		if err != nil || !cfg.UI || cfg.UINoBrowser != noBrowser {
			t.Fatalf("headless flag: %+v, %v", cfg, err)
		}
	}
}

func TestSudoBrowserUsesInvokingUserSession(t *testing.T) {
	address := "http://127.0.0.1:54321/#session"
	for _, platform := range []string{"darwin", "linux"} {
		program, args := sudoBrowserCommand(platform, address, "501", "/Users/example")
		if args[len(args)-1] != address {
			t.Fatal("lost complete session URL")
		}
		foundUser := false
		for i, arg := range args {
			if arg == "-u" && i+1 < len(args) && args[i+1] == "#501" {
				foundUser = true
			}
		}
		if !foundUser {
			t.Fatal("browser would run as root")
		}
		if platform == "darwin" && (program != "/bin/launchctl" || args[0] != "asuser" || args[1] != "501") {
			t.Fatal("missing macOS GUI session")
		}
	}
}
