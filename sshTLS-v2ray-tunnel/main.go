package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	cfg, err := parseConfig(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if shouldDropUIPrivileges(cfg) {
		if err := runUnprivilegedUI(ctx, cfg); err != nil {
			log.Fatal(err)
		}
		return
	}
	if cfg.UI {
		if err := serveControl(ctx, cfg.UIPort, cfg.UIReadyFile, cfg.UINoBrowser, cfg.UIHelper, cfg.UIHelperAddressFile); err != nil {
			log.Fatal(err)
		}
		return
	}
	client := NewVPNClient(cfg)
	go func() {
		select {
		case <-ctx.Done():
			client.Cancel()
		case <-client.ctx.Done():
		}
	}()
	if err := client.Start(); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}
