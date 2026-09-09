#!/usr/bin/env python3
"""Record locked Rust dependencies and their locally installed licence texts."""
import json
import pathlib
import subprocess

root = pathlib.Path(__file__).resolve().parent.parent
metadata = json.loads(subprocess.check_output([
    str(root / 'scripts/rust.sh'), 'metadata', '--manifest-path', 'rust/Cargo.toml',
    '--locked', '--format-version', '1'
], cwd=root))
packages = sorted((p for p in metadata['packages'] if p['source']), key=lambda p: p['name'])
lines = ['# Third-party Rust dependencies', '',
         'Generated from Cargo.lock and cargo metadata. Project-owned code has no public-source licence selected.',
         'Licence expressions below are upstream metadata; each upstream licence text and notice still applies.',
         'This inventory is not a patent-clearance opinion or a vulnerability audit.', '',
         '| Crate | Version | Declared licence |', '|---|---|---|']
for package in packages:
    lines.append(f"| {package['name']} | {package['version']} | {package['license'] or 'See upstream licence file'} |")
for package in packages:
    directory = pathlib.Path(package['manifest_path']).parent
    files = sorted({p for pattern in ('LICENSE*', 'LICENCE*', 'COPYING*', 'NOTICE*')
                    for p in directory.glob(pattern) if p.is_file()})
    if package.get('license_file'):
        declared = directory / package['license_file']
        if declared.is_file() and declared not in files:
            files.append(declared)
    lines.extend(['', f"## {package['name']} {package['version']}", '',
                  f"Upstream: {package.get('repository') or package.get('homepage') or 'https://crates.io/crates/' + package['name']}", ''])
    if not files:
        lines.append('No top-level licence text was present in the downloaded crate. Consult upstream before redistribution.')
    for file in files:
        lines.extend([f'### {file.name}', '', '```text', '\n'.join(line.rstrip() for line in file.read_text(errors='replace').splitlines()).rstrip(), '```', ''])
(root / 'Documentation/THIRD_PARTY_NOTICES.md').write_text('\n'.join(lines).rstrip() + '\n')
print(f'Recorded {len(packages)} dependency packages')
