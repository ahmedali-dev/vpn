#!/usr/bin/env bash
set -euo pipefail
# All interface, route and firewall changes stay inside disposable namespaces.
root_dir="$(cd "$(dirname "$0")/.." && pwd)"
core="$root_dir/dist/runtime/${TUNNEL_PACKAGE_TARGET:?}/cores/sing-box"
test_binary="$(mktemp /tmp/tunnelnest-network.XXXXXX)"
trap 'rm -f "$test_binary"' EXIT
go test -c -o "$test_binary" .
sudo modprobe tun
sudo modprobe nf_tables
sudo modprobe nfnetlink_queue
sudo unshare --net --mount --fork /bin/bash -c '
 set -euo pipefail
 mount --make-rprivate /
 mount -t tmpfs tmpfs /run
 ip link set lo up
 ip link add uplink0 type dummy
 ip addr add 192.0.2.1/24 dev uplink0
 ip link set uplink0 up
 ip route add default via 192.0.2.2 dev uplink0
 TUNNEL_NAMESPACE_TEST=1 TUNNEL_TEST_CORE="$1" "$2" -test.run "^TestLinuxFullDeviceCapture$" -test.v -test.timeout 70s
' -- "$core" "$test_binary"
