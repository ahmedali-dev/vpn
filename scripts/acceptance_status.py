#!/usr/bin/env python3
"""Check local device acceptance evidence. Never starts a VPN or changes networking."""
import argparse
import json
from pathlib import Path

SCENARIOS = ('sleep-wake', 'network-change', 'core-crash')
MANUAL = ('windowOpened', 'elevationPrompt', 'routingRulesChecked', 'cleanupInspected')

def assess(root):
    findings = []
    def load(path):
        if not path.is_file():
            findings.append({'check': str(path.relative_to(root)), 'status': 'missing'})
            return None
        try:
            value = json.loads(path.read_text())
            if not isinstance(value, dict):
                raise ValueError('expected a JSON object')
            return value
        except (ValueError, OSError):
            findings.append({'check': str(path.relative_to(root)), 'status': 'invalid'})
            return None
    for label in ('before', 'connected', 'after'):
        value = load(root / 'normal' / (label + '.json'))
        if value is not None:
            passed = value.get('pass') is True
            if label == 'after':
                passed = passed and value.get('tunAddressRemains') is False and value.get('cleanupInspectionSucceeded') is True
            findings.append({'check': label, 'status': 'passed' if passed else 'failed'})
    for scenario in SCENARIOS:
        value = load(root / scenario / 'summary.json')
        if value is not None:
            samples = value.get('samples')
            passed = (type(samples) is int and samples > 0 and type(value.get('failedSamples')) is int and value['failedSamples'] == 0
                      and value.get('unrecoveredFailure') is False and value.get('interrupted') is False)
            # Recovery after an interruption remains a failed soak if any sample failed.
            findings.append({'check': scenario, 'status': 'passed' if passed else 'failed'})
    operator = load(root / 'operator.json')
    if operator is not None:
        metadata = all(isinstance(operator.get(k), str) and operator[k].strip()
                       for k in ('osVersion', 'architecture', 'appVersion', 'mode', 'routing'))
        findings.append({'check': 'device metadata', 'status': 'reported' if metadata else 'missing'})
        for key in MANUAL:
            findings.append({'check': key, 'status': 'reported' if operator.get(key) is True else 'pending'})
    complete = all(f['status'] in ('passed', 'reported') for f in findings)
    return {'complete': complete, 'checks': findings,
            'scope': 'One device/profile/mode; operator checks are reported, not independently verified.',
            'note': 'Passing evidence does not prove absence of all leaks or a persistent kill switch.'}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    result = assess(args.directory)
    print(json.dumps(result, indent=2))
    return 0 if result['complete'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
