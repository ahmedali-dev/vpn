package main

import (
	"encoding/json"
	"testing"
)

func TestLinuxRedirectPreservesUpstreamExclusions(t *testing.T) {
	for _, platform := range []string{"linux", "darwin", "windows"} {
		t.Run(platform, func(t *testing.T) {
			data, err := generateTUNConfigForPlatform(Config{Mode: ModeSSH, SOCKSPort: 1082}, []string{"51.75.74.253/32"}, platform)
			if err != nil {
				t.Fatal(err)
			}
			var config struct {
				Inbounds []struct {
					AutoRoute    bool     `json:"auto_route"`
					AutoRedirect bool     `json:"auto_redirect"`
					Excluded     []string `json:"route_exclude_address"`
				}
				Route struct {
					AutoDetect bool `json:"auto_detect_interface"`
				}
			}
			if err = json.Unmarshal(data, &config); err != nil {
				t.Fatal(err)
			}
			if len(config.Inbounds) != 1 {
				t.Fatal("missing TUN inbound")
			}
			inbound := config.Inbounds[0]
			if inbound.AutoRedirect != (platform == "linux") {
				t.Fatalf("incorrect platform redirection: %s", data)
			}
			if !inbound.AutoRoute || !config.Route.AutoDetect || len(inbound.Excluded) != 1 || inbound.Excluded[0] != "51.75.74.253/32" {
				t.Fatal("redirect lost upstream loop prevention")
			}
		})
	}
}
