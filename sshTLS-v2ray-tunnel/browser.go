package main

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
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
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	// Pass the complete URL as one argument, including its private session fragment.
	// No shell is involved and opener output must not expose the session token.
	return exec.CommandContext(ctx, program, args...).Run()
}
