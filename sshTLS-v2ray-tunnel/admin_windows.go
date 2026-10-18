//go:build windows

package main

import "syscall"

var isUserAnAdmin = syscall.NewLazyDLL("shell32.dll").NewProc("IsUserAnAdmin")

func isAdmin() bool { result, _, _ := isUserAnAdmin.Call(); return result != 0 }
