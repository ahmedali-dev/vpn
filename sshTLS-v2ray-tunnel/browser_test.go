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
