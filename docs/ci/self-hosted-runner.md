# ActiveChain self-hosted CI runner

ActiveChain CI executes on a dedicated repository-scoped runner on the development Mac. It does not share registration or labels with the other runners on the machine.

## Registered runner

| Property | Value |
|---|---|
| Name | `activechain-mac-arm64` |
| Repository | `advatar/ActiveChain` |
| Labels | `self-hosted`, `macOS`, `ARM64`, `activechain-ci` |
| Runner version | `2.335.1` |
| Installation | `/Users/johansellstrom/actions-runner-activechain` |
| Work directory | `/Users/johansellstrom/actions-runner-activechain/_work` |
| LaunchAgent | `actions.runner.advatar-ActiveChain.activechain-mac-arm64` |
| Automatic runner updates | Disabled |

The retained distribution archive was verified against SHA-256 `e1a9bc7a3661e06fa0b129d15c2064fe65dc81a431001d8958a9db1409b73769` before extraction.

The runner uses the host's pinned `rustup` and `elan` installations. The workflow installs Rust 1.97.1 and Lean 4.32.0 by exact version, then builds the Rust kernel, the executable Lean APL model, and their shared frozen truth table entirely on this machine.

## Operations

Inspect GitHub registration:

```sh
gh api repos/advatar/ActiveChain/actions/runners \
  --jq '.runners[] | [.name,.os,.status,.busy,([.labels[].name]|join(","))] | @tsv'
```

Inspect the local service:

```sh
launchctl list | rg actions.runner.advatar-ActiveChain.activechain-mac-arm64
```

Start, stop, or inspect the runner from its installation directory:

```sh
cd /Users/johansellstrom/actions-runner-activechain
./svc.sh status
./svc.sh start
./svc.sh stop
```

Upgrades are deliberate: verify a new official release archive and checksum, stop the service, replace the runner distribution, and restart it. Registration tokens are short-lived and MUST NOT be written to this repository or logs.

## Security boundary

Self-hosted jobs execute with the local user account's permissions. Accordingly:

- the runner is repository-scoped and selected by its unique `activechain-ci` label;
- workflow permissions remain read-only unless a reviewed job explicitly needs more;
- checkout credentials are not persisted;
- pull-request workflow changes require the same scrutiny as local scripts;
- secrets MUST NOT be exposed to untrusted pull-request code;
- the runner worktree is treated as disposable build state, never canonical project state.

Disabling automatic runner updates makes the binary version auditable, but requires prompt manual upgrades when GitHub raises the minimum supported runner version or publishes a security fix.
