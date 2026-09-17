#!/usr/bin/env python3
"""Prove the capability checker refuses false claims.

A checker that only ever passes is worth nothing, so each case below is a
manifest that must be rejected, plus one that must be accepted.
"""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / 'tools/check_capabilities.py'

VALID = {
    'id': 'sample-capability',
    'title': 'A sample capability',
    'maturity': 'IMPLEMENTED',
    'gates': ['G3'],
    'scope': 'Something narrow and checkable.',
    'assumptions': ['The fixture is synthetic.'],
    'verification': [{'command': "python3 -c \"print('test result: ok. 3 passed; 0 failed;')\"",
                      'expect_tests': 3, 'description': 'A stand-in cargo gate.'}],
    'known_failures': ['Does not cover a device build.'],
    'clinical_use': 'none',
    'last_reviewed': '2026-09-17',
}


def check(manifest, run, name='sample-capability'):
    """Run the checker over one manifest and return (exit code, output)."""
    with tempfile.TemporaryDirectory(prefix='invivo-capabilities-') as directory:
        (Path(directory) / f'{name}.json').write_text(json.dumps(manifest))
        command = [sys.executable, str(CHECKER), '--dir', directory] + (['--run'] if run else [])
        finished = subprocess.run(command, capture_output=True, text=True, cwd=ROOT)
        return finished.returncode, finished.stdout + finished.stderr


def altered(**changes):
    manifest = deepcopy(VALID)
    manifest.update(changes)
    return manifest


REFUSALS = [
    ('a claim with no stated limitation', altered(known_failures=[])),
    ('IMPLEMENTED with no counted evidence',
     altered(verification=[{'command': 'true', 'description': 'No count.'}])),
    ('TARGET that still claims evidence', altered(maturity='TARGET')),
    ('TARGET claiming clinical use',
     altered(maturity='TARGET', verification=[], known_failures=[], clinical_use='clinical')),
    ('clinical use without qualification', altered(clinical_use='clinical')),
    ('an unknown maturity', altered(maturity='PRODUCTION')),
    ('an id that does not match its filename', altered(id='another-capability')),
    ('a gate id that is not a PRODUCTION.md gate', altered(gates=['wave-one'])),
    ('a dependency that does not resolve', altered(dependencies=['no-such-capability'])),
    ('a missing required field', {key: value for key, value in VALID.items() if key != 'scope'}),
    ('an empty assumption list', altered(assumptions=[])),
    ('a malformed review date', altered(last_reviewed='September 2026')),
]

EXECUTION_REFUSALS = [
    ('a gate that fails', altered(verification=[
        {'command': 'exit 1', 'expect_tests': 3, 'description': 'Broken gate.'}])),
    ('evidence that shrank below the claim', altered(verification=[
        {'command': "python3 -c \"print('OK (2 tests)')\"", 'expect_tests': 3,
         'description': 'Fewer tests than claimed.'}])),
    ('evidence that grew beyond the claim', altered(verification=[
        {'command': "python3 -c \"print('OK (9 tests)')\"", 'expect_tests': 3,
         'description': 'More tests than claimed.'}])),
    ('a gate with no readable test count', altered(verification=[
        {'command': "python3 -c \"print('done')\"", 'expect_tests': 3,
         'description': 'Unreadable output.'}])),
    ('a cargo run that passed the wrong number', altered(verification=[
        {'command': "python3 -c \"print('test result: ok. 4 passed; 0 failed;')\"",
         'expect_tests': 3, 'description': 'Cargo count differs from the claim.'}])),
    ('a cargo run with failures', altered(verification=[
        {'command': "python3 -c \"print('test result: ok. 3 passed; 1 failed;')\"",
         'expect_tests': 3, 'description': 'Cargo reported a failure.'}])),
]


def main():
    failures = []
    code, output = check(VALID, run=True)
    if code != 0:
        failures.append(f'the valid manifest was refused:\n{output}')

    for description, manifest in REFUSALS:
        # Always written as sample-capability.json, so a manifest whose own id
        # differs is genuinely a filename mismatch.
        code, output = check(manifest, run=False)
        if code == 0:
            failures.append(f'accepted {description}')

    for description, manifest in EXECUTION_REFUSALS:
        code, output = check(manifest, run=True)
        if code == 0:
            failures.append(f'accepted {description}')
        # Without --run the manifest is well-formed, so only execution may refuse it.
        code, _ = check(manifest, run=False)
        if code != 0 and 'no readable' not in description:
            failures.append(f'{description} was refused before its gate even ran')

    for failure in failures:
        print(f'FAIL {failure}', file=sys.stderr)
    if failures:
        raise SystemExit(1)
    print(f'OK ({1 + len(REFUSALS) + len(EXECUTION_REFUSALS) * 2} tests)')


if __name__ == '__main__':
    main()
