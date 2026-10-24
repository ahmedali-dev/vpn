package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"time"
)

func controlBrowserCommand(platform, address string) (string, []string, error) {
	switch platform {
	case "darwin":
		return "open", []string{address}, nil
	case "windows":
		return "rundll32.exe", []string{"url.dll,FileProtocolHandler", address}, nil
	case "linux":
		return "xdg-open", []string{address}, nil
	default:
		return "", nil, fmt.Errorf("browser opening is unsupported on %s", platform)
	}
}

func openControlBrowser(ctx context.Context, address string) error {
	program, args, err := controlBrowserCommand(runtime.GOOS, address)
	if err != nil {
		return err
	}
	if isAdmin() && runtime.GOOS != "windows" && os.Getenv("SUDO_UID") != "" {
		uid := os.Getenv("SUDO_UID")
		id, parseErr := strconv.ParseUint(uid, 10, 32)
		if parseErr != nil || id == 0 {
			return fmt.Errorf("invalid sudo browser user")
		}
		account, lookupErr := user.LookupId(uid)
		if lookupErr != nil {
			return fmt.Errorf("cannot find sudo browser user: %w", lookupErr)
		}
		program, args = sudoBrowserCommand(runtime.GOOS, address, uid, account.HomeDir)
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	// Pass the complete URL as one argument, including its private session fragment.
	// No shell is involved and opener output must not expose the session token.
	return exec.CommandContext(ctx, program, args...).Run()
}

func sudoBrowserCommand(platform, address, uid, home string) (string, []string) {
	if platform == "darwin" {
		// Enter the invoking user's GUI session, then drop root before opening a URL.
		return "/bin/launchctl", []string{"asuser", uid, "/usr/bin/sudo", "-H", "-u", "#" + uid, "/usr/bin/open", address}
	}
	return "/usr/bin/sudo", []string{"-H", "-u", "#" + uid, "--", "env", "HOME=" + home, "XDG_RUNTIME_DIR=/run/user/" + uid, "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/" + uid + "/bus", "xdg-open", address}
}
