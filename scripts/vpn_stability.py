#!/usr/bin/env python3
"""Read-only Windows/Linux VPN routing snapshots and soak tests. Never connects a VPN or changes routes."""
import argparse
import datetime
import ipaddress
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time


def command(args, timeout=15):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return {'ok': result.returncode == 0, 'output': result.stdout[:131072], 'error': result.stderr[:2048]}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'ok': False, 'output': '', 'error': str(error)}


def public_ip(proxy=None, ipv6=False):
    args = ['curl.exe' if os.name == 'nt' else 'curl', '-q', '--silent', '--show-error', '--fail',
            '--http1.1', '--max-time', '12', '-6' if ipv6 else '-4']
    if proxy:
        args += ['--proxy', proxy, '--noproxy', '']
    else:
        args += ['--noproxy', '*']
    started = time.monotonic()
    result = command(args + ['https://api6.ipify.org' if ipv6 else 'https://api.ipify.org'])
    result['durationMs'] = round((time.monotonic() - started) * 1000)
    result['ip'] = None
    if result['ok']:
        try:
            value = ipaddress.ip_address(result['output'].strip())
            if value.version != (6 if ipv6 else 4):
                raise ValueError('Unexpected IP address family')
            result['ip'] = str(value)
        except ValueError as error:
            result.update(ok=False, error=str(error))
    result.pop('output')
    return result


def dns():
    # Isolate getaddrinfo so an unresponsive system resolver has a real deadline.
    return command([sys.executable, '-c',
                    'import socket,json; print(json.dumps(sorted({a[4][0] for a in socket.getaddrinfo("example.com",443)})))'], 10)


def routing():
    if os.name == 'nt':
        return {'routes': command(['route.exe', 'print']),
                'addresses': command(['ipconfig.exe', '/all'])}
    return {'routes4': command(['ip', '-4', 'route', 'show', 'table', 'all']),
            'routes6': command(['ip', '-6', 'route', 'show', 'table', 'all']),
            'rules': command(['ip', 'rule', 'show']),
            'rules6': command(['ip', '-6', 'rule', 'show']),
            'addresses': command(['ip', '-j', 'address', 'show'])}


def sample(args, include_routes=False):
    proxy = 'socks5h://127.0.0.1:' + str(args.socks_port)
    system = public_ip()
    socks = public_ip(proxy)
    routed = system if args.routing == 'tun' else socks
    passed = routed['ok'] and routed['ip'] == args.expected_ip
    if args.routing == 'tun':
        passed = passed and socks['ok'] and system['ip'] == socks['ip']
    resolver = dns()
    passed = passed and resolver['ok']
    result = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'mode': args.mode, 'routing': args.routing, 'system': system,
              'socks': socks, 'dns': resolver, 'pass': bool(passed)}
    if include_routes:
        result['network'] = routing()
        result['ipv6'] = public_ip(ipv6=True)
        result['ipv6Status'] = ('blocked-or-unavailable' if not result['ipv6']['ok']
                               else 'matches-expected' if args.expected_ipv6 == result['ipv6']['ip']
                               else 'mismatch' if args.expected_ipv6 else 'unverified-set-expected-ipv6')
        if args.routing == 'tun' and result['ipv6Status'] == 'mismatch':
            result['pass'] = False
    return result


class Summary:
    def __init__(self):
        self.samples = self.failures = self.longest_failure = self.streak = 0
        self.failed_at = None
        self.recoveries = []

    def add(self, passed, elapsed):
        self.samples += 1
        if passed:
            if self.failed_at is not None:
                self.recoveries.append(round(elapsed - self.failed_at, 3))
            self.failed_at = None
            self.streak = 0
        else:
            self.failures += 1
            self.streak += 1
            self.longest_failure = max(self.longest_failure, self.streak)
            if self.failed_at is None:
                self.failed_at = elapsed

    def report(self):
        return {'samples': self.samples, 'failedSamples': self.failures,
                'longestFailureStreak': self.longest_failure, 'recoverySeconds': self.recoveries,
                'unrecoveredFailure': self.failed_at is not None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['snapshot', 'soak'])
    parser.add_argument('--label', choices=['before', 'connected', 'after'], default='connected')
    parser.add_argument('--mode', choices=['ssh', 'xray', 'v2ray'], required=True)
    parser.add_argument('--routing', choices=['proxy', 'tun'], required=True)
    parser.add_argument('--socks-port', type=int, default=1080)
    parser.add_argument('--expected-ip', required=True, help='Expected exit IPv4; before/after snapshots use your normal IP')
    parser.add_argument('--expected-ipv6', help='Expected VPN exit IPv6, if available')
    parser.add_argument('--duration', type=int, default=28800, help='Soak duration in seconds; default eight hours')
    parser.add_argument('--interval', type=int, default=30, help='Minimum seconds between samples')
    parser.add_argument('--output', type=Path, required=True, help='Local output directory; may contain public IPs and route details')
    args = parser.parse_args()
    if platform.system() not in ('Windows', 'Linux'):
        parser.error('Run routing validation on Windows or Linux')
    if not 1 <= args.socks_port <= 65535 or args.duration < 1 or args.interval < 1:
        parser.error('Invalid port, duration or interval')
    try:
        if ipaddress.ip_address(args.expected_ip).version != 4:
            raise ValueError('expected-ip must be IPv4')
        if args.expected_ipv6 and ipaddress.ip_address(args.expected_ipv6).version != 6:
            raise ValueError('expected-ipv6 must be IPv6')
    except ValueError as error:
        parser.error(str(error))
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.operation == 'snapshot':
        result = sample(args, include_routes=True)
        if args.label != 'connected':
            # No SOCKS listener is expected when disconnected.
            result['pass'] = result['system']['ok'] and result['system']['ip'] == args.expected_ip and result['dns']['ok']
        path = args.output / (args.label + '.json')
        path.write_text(json.dumps(result, indent=2) + '\n')
        print(str(path) + ': ' + ('PASS' if result['pass'] else 'FAIL'))
        return 0 if result['pass'] else 1
    start = time.monotonic()
    summary = Summary()
    interrupted = False
    try:
        with (args.output / 'soak.jsonl').open('w', buffering=1) as stream:
            while time.monotonic() - start < args.duration:
                tick = time.monotonic()
                result = sample(args, include_routes=summary.samples == 0)
                result['elapsedSeconds'] = round(time.monotonic() - start, 3)
                summary.add(result['pass'], result['elapsedSeconds'])
                stream.write(json.dumps(result) + '\n')
                print(result['at'] + ' ' + ('PASS' if result['pass'] else 'FAIL'), flush=True)
                remaining = args.duration - (time.monotonic() - start)
                if remaining > 0:
                    time.sleep(min(remaining, max(0, args.interval - (time.monotonic() - tick))))
    except KeyboardInterrupt:
        interrupted = True
    report = summary.report()
    report.update(interrupted=interrupted, durationSeconds=round(time.monotonic() - start, 3))
    (args.output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 1 if interrupted or summary.failures or not summary.samples else 0


if __name__ == '__main__':
    sys.exit(main())
