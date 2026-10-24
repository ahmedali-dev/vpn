//go:build windows

package main

import "context"

func shouldDropUIPrivileges(Config) bool              { return false }
func runUnprivilegedUI(context.Context, Config) error { return nil }
