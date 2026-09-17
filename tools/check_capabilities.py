#!/usr/bin/env python3
"""Validate capability manifests, and optionally run the evidence they claim.

PRODUCTION.md G18: maturity should be an executable release property, so a claim
can be refuted by a checker instead of classified by hand. See
capabilities/SCHEMA.md for the rules enforced here.

    python3 tools/check_capabilities.py           # validate manifests only
    python3 tools/check_capabilities.py --run     # also execute every declared gate
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = ROOT / 'capabilities'
MATURITIES = ('IMPLEMENTED', 'DEMONSTRATED', 'RESEARCH', 'TARGET')
CLINICAL_USE = ('none', 'research_only', 'clinical')
REQUIRED_TEXT = ('id', 'title', 'maturity', 'scope', 'clinical_use', 'last_reviewed')
REQUIRED_LIST = ('gates', 'assumptions', 'verification', 'known_failures')
# Swift Testing, JUnit and cargo all report their totals differently. A cargo run
# prints one `test result` line per test binary, so the counts are summed.
COUNTS = (re.compile(r'Test run with (\d+) tests? in \d+ suites? passed'),
          re.compile(r'^OK \((\d+) tests?\)', re.MULTILINE))
CARGO = re.compile(r'^test result: ok\. (\d+) passed; (\d+) failed;', re.MULTILINE)


def load(path):
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as error:
        raise SystemExit(f'{path.name}: invalid JSON: {error}')


def validate(path, manifest, identities):
    """Return a list of human-readable problems with one manifest."""
    problems = []

    def require(condition, message):
        if not condition:
            problems.append(f'{path.name}: {message}')

    for field in REQUIRED_TEXT:
        require(isinstance(manifest.get(field), str) and manifest[field].strip(),
                f'{field} must be a non-empty string')
    for field in REQUIRED_LIST:
        require(isinstance(manifest.get(field), list), f'{field} must be a list')
    if problems:
        return problems

    require(manifest['id'] == path.stem, f'id {manifest["id"]!r} must match the filename')
    require(re.fullmatch(r'[a-z0-9]+(-[a-z0-9]+)*', manifest['id']), 'id must be kebab-case')
    require(manifest['maturity'] in MATURITIES, f'maturity must be one of {", ".join(MATURITIES)}')
    require(manifest['clinical_use'] in CLINICAL_USE, f'clinical_use must be one of {", ".join(CLINICAL_USE)}')
    require(re.fullmatch(r'\d{4}-\d{2}-\d{2}', manifest['last_reviewed']), 'last_reviewed must be an ISO date')
    require(manifest['gates'] and all(re.fullmatch(r'G\d+', gate) for gate in manifest['gates']),
            'gates must be a non-empty list of PRODUCTION.md gate ids')
    require(bool(manifest['assumptions']), 'assumptions must not be empty')

    maturity = manifest['maturity']
    verification = manifest['verification']
    for index, gate in enumerate(verification):
        label = f'verification[{index}]'
        if not isinstance(gate, dict):
            problems.append(f'{path.name}: {label} must be an object')
            continue
        require(isinstance(gate.get('command'), str) and gate['command'].strip(),
                f'{label}.command must be a non-empty string')
        require(isinstance(gate.get('description'), str) and gate['description'].strip(),
                f'{label}.description must be a non-empty string')
        if 'expect_tests' in gate:
            require(isinstance(gate['expect_tests'], int) and gate['expect_tests'] > 0,
                    f'{label}.expect_tests must be a positive integer')

    if maturity == 'IMPLEMENTED':
        require(any('expect_tests' in gate for gate in verification if isinstance(gate, dict)),
                'IMPLEMENTED requires at least one verification gate with expect_tests')
    elif maturity == 'DEMONSTRATED':
        require(bool(verification), 'DEMONSTRATED requires at least one verification gate')
    elif maturity == 'TARGET':
        require(not verification, 'TARGET must declare no verification; it is not built yet')
        require(manifest['clinical_use'] != 'clinical', 'TARGET may not declare clinical use')

    require(maturity == 'TARGET' or bool(manifest['known_failures']),
            'known_failures must not be empty; claiming no limitation is itself a claim')
    if manifest['clinical_use'] == 'clinical':
        require(maturity == 'IMPLEMENTED', 'clinical use requires IMPLEMENTED maturity')
        require(any('qualification' in str(item).lower() for item in manifest.get('dependencies', [])),
                'clinical use requires an explicit qualification dependency')

    for dependency in manifest.get('dependencies', []):
        # A bare kebab-case token names another capability; anything else is an
        # external pin such as an upstream commit, which this checker cannot verify.
        if re.fullmatch(r'[a-z0-9]+(-[a-z0-9]+)*', str(dependency)) and dependency not in identities:
            problems.append(f'{path.name}: dependency {dependency!r} does not resolve')
    return problems


def run_gate(manifest, gate):
    """Execute one declared gate and return a problem string, or None."""
    command = gate['command']
    finished = subprocess.run(command, shell=True, cwd=ROOT, capture_output=True, text=True)
    output = finished.stdout + finished.stderr
    if finished.returncode != 0:
        tail = '\n'.join(output.strip().splitlines()[-5:])
        return f'{manifest["id"]}: gate failed ({command}):\n{tail}'
    expected = gate.get('expect_tests')
    if expected is None:
        return None
    cargo = CARGO.findall(output)
    if cargo:
        if any(int(failed) for _, failed in cargo):
            return f'{manifest["id"]}: gate reported failing tests ({command})'
        actual = sum(int(passed) for passed, _ in cargo)
        if actual != expected:
            return (f'{manifest["id"]}: gate reported {actual} passing tests but the manifest claims '
                    f'{expected} ({command}). Update the manifest deliberately, or restore the evidence.')
        return None
    for pattern in COUNTS:
        found = pattern.search(output)
        if found:
            actual = int(found.group(1))
            if actual != expected:
                return (f'{manifest["id"]}: gate reported {actual} tests but the manifest claims '
                        f'{expected} ({command}). Update the manifest deliberately, or restore the evidence.')
            return None
    return f'{manifest["id"]}: could not read a test count from ({command}); expected {expected}'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', help='execute every declared verification gate')
    parser.add_argument('--dir', type=Path, default=MANIFESTS,
                        help='manifest directory; used by the checker self-test')
    arguments = parser.parse_args()

    paths = sorted(arguments.dir.glob('*.json'))
    if not paths:
        raise SystemExit(f'No capability manifests found in {arguments.dir}')
    manifests = {path: load(path) for path in paths}
    identities = {manifest.get('id') for manifest in manifests.values()}

    problems = []
    seen = {}
    for path, manifest in manifests.items():
        problems += validate(path, manifest, identities)
        identity = manifest.get('id')
        if identity in seen:
            problems.append(f'{path.name}: duplicate id {identity!r}, also in {seen[identity]}')
        seen[identity] = path.name

    if arguments.run and not problems:
        for path, manifest in manifests.items():
            for gate in manifest['verification']:
                print(f'  {manifest["id"]}: {gate["command"]}', flush=True)
                failure = run_gate(manifest, gate)
                if failure:
                    problems.append(failure)

    for problem in problems:
        print(f'FAIL {problem}', file=sys.stderr)
    if problems:
        raise SystemExit(1)

    counts = {}
    for manifest in manifests.values():
        counts[manifest['maturity']] = counts.get(manifest['maturity'], 0) + 1
    summary = ', '.join(f'{counts[name]} {name}' for name in MATURITIES if name in counts)
    verb = 'validated and executed' if arguments.run else 'validated'
    print(f'{len(manifests)} capability manifests {verb}: {summary}')


if __name__ == '__main__':
    main()
