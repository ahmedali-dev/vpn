"""Test stability reporting without touching networking or running a VPN."""
import argparse
import unittest
from unittest import mock
import vpn_stability as stability


class StabilityReportTests(unittest.TestCase):
    def test_recovers_after_outage_and_tracks_unrecovered_failures(self):
        summary = stability.Summary()
        for passed, elapsed in [(True, 0), (False, 10), (False, 20), (True, 30), (False, 40)]:
            summary.add(passed, elapsed)
        self.assertEqual(summary.report(), dict(samples=5, failedSamples=3, longestFailureStreak=2,
                                               recoverySeconds=[20], unrecoveredFailure=True))

    @mock.patch.object(stability, 'dns', return_value={'ok': True})
    @mock.patch.object(stability, 'public_ip')
    def test_passing_socks_cannot_hide_broken_tun(self, probe, resolver):
        probe.side_effect = [{'ok': True, 'ip': '192.0.2.1'}, {'ok': True, 'ip': '192.0.2.2'}]
        args = argparse.Namespace(socks_port=1080, routing='tun', mode='ssh', expected_ip='192.0.2.2')
        self.assertFalse(stability.sample(args)['pass'])

    @mock.patch.object(stability, 'command', return_value={'ok': True, 'output': 'not an address', 'error': ''})
    def test_invalid_ip_response_is_not_counted_as_success(self, command):
        self.assertFalse(stability.public_ip()['ok'])
        self.assertIn('--noproxy', command.call_args[0][0])

    @mock.patch.object(stability, 'command', return_value={'ok': True, 'output': '192.0.2.2', 'error': ''})
    def test_proxy_probe_explicitly_overrides_environment_bypass(self, command):
        self.assertTrue(stability.public_ip('socks5h://127.0.0.1:1080')['ok'])
        args = command.call_args[0][0]
        self.assertEqual(args[args.index('--noproxy') + 1], '')


class MacRoutingTests(unittest.TestCase):
    @mock.patch.object(stability.os, 'name', 'posix')
    @mock.patch.object(stability.platform,'system',return_value='Darwin')
    @mock.patch.object(stability,'command',return_value={'ok':True,'output':'','error':''})
    def test_macos_snapshot_uses_read_only_native_inspection(self,command,system):
        self.assertIn('routes',stability.routing())
        self.assertEqual(command.call_args_list[0].args[0],['/usr/sbin/netstat','-rn'])
        self.assertEqual(command.call_args_list[1].args[0],['/sbin/ifconfig'])


class PlatformRoutingTests(unittest.TestCase):
    @mock.patch.object(stability.os, 'name', 'nt')
    @mock.patch.object(stability.platform, 'system', return_value='Windows')
    @mock.patch.object(stability, 'command', return_value={'ok': True, 'output': '', 'error': ''})
    def test_windows_snapshot_uses_read_only_native_inspection(self, command, system):
        self.assertIn('routes', stability.routing())
        self.assertEqual(command.call_args_list, [
            mock.call(['route.exe', 'print']),
            mock.call(['ipconfig.exe', '/all']),
        ])

    @mock.patch.object(stability.os, 'name', 'posix')
    @mock.patch.object(stability.platform, 'system', return_value='Linux')
    @mock.patch.object(stability, 'command', return_value={'ok': True, 'output': '', 'error': ''})
    def test_linux_snapshot_inspects_both_address_families_and_rules(self, command, system):
        self.assertIn('routes4', stability.routing())
        self.assertEqual(command.call_args_list, [
            mock.call(['ip', '-4', 'route', 'show', 'table', 'all']),
            mock.call(['ip', '-6', 'route', 'show', 'table', 'all']),
            mock.call(['ip', 'rule', 'show']),
            mock.call(['ip', '-6', 'rule', 'show']),
            mock.call(['ip', '-j', 'address', 'show']),
        ])
