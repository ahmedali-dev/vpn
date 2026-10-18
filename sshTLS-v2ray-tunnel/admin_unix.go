//go:build !windows

package main

import "os"

func isAdmin() bool { return os.Geteuid() == 0 }
