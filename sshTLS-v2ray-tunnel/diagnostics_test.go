package main

import (
	"strings"
	"testing"
)

func TestDiagnosticsRedactsCredentialsAndEndpoints(t *testing.T) {
	input := "password secret-value server 51.75.74.253 host server.example.com https://user:pass@example.com/#token"
	output := redactDiagnostics(input, "secret-value")
	for _, private := range []string{"secret-value", "51.75.74.253", "server.example.com", "user:pass", "token"} {
		if strings.Contains(output, private) {
			t.Fatalf("diagnostic leaked %s", private)
		}
	}
}
