//go:build !windows

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"time"
)

// Keep the UI and database under the invoking user even when the CLI uses sudo.
func shouldDropUIPrivileges(cfg Config) bool {
	return isAdmin() && cfg.UI && !cfg.UIHelper && cfg.UIReadyFile == "" && os.Getenv("SUDO_UID") != ""
}
func runUnprivilegedUI(ctx context.Context, cfg Config) error {
	uid, err := strconv.Atoi(os.Getenv("SUDO_UID"))
	if err != nil || uid <= 0 {
		return fmt.Errorf("invalid sudo user")
	}
	account, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "tunnelnest-user-ui-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err = os.Chown(dir, uid, gid); err != nil {
		return err
	}
	ready := filepath.Join(dir, "helper")
	if err = os.WriteFile(ready, nil, 0600); err != nil {
		return err
	}
	if err = os.Chown(ready, uid, gid); err != nil {
		return err
	}
	helperCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveControl(helperCtx, 0, ready, true, true, "") }()
	for i := 0; i < 150; i++ {
		data, _ := os.ReadFile(ready)
		if len(data) > 0 {
			break
		}
		select {
		case err := <-done:
			return err
		default:
		}
		if !sleepContext(ctx, 100*time.Millisecond) {
			return ctx.Err()
		}
	}
	data, _ := os.ReadFile(ready)
	if len(data) == 0 {
		return fmt.Errorf("privileged helper did not become ready")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"-H", "-u", "#" + strconv.Itoa(uid), "--", exe, "-ui", "-ui-helper-address-file", ready, "-ui-port", strconv.Itoa(cfg.UIPort)}
	if cfg.UINoBrowser {
		args = append(args, "-ui-no-browser")
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/sudo", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	cancel()
	<-done
	return err
}
