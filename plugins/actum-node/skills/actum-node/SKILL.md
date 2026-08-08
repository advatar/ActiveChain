---
name: actum-node
description: Build, start, stop, inspect, and query an Actum or ActiveChain RPC node. Use for Actum node installation, local node lifecycle, logs, health, finalized height, chain identity, testnet status, or the Actum MCP interface.
license: Apache-2.0
compatibility: Requires Python 3.11+. Building binaries requires Rust 1.97.1 and Cargo; querying requires TCP access to the node.
metadata:
  author: activechain-contributors
  version: "0.1.0"
---

# Actum node operations

Use `scripts/actum-node` from this skill directory. It emits machine-readable JSON except for
`logs`. Never infer success from a PID alone: use `status` or `query`.

## Build

From an ActiveChain source checkout:

```sh
scripts/actum-node build --source /path/to/ActiveChain
```

This builds the existing `activechain-rpc-node`, `activechain-rpc-probe`, and `activechain-mcp`
binaries in release mode. It does not download source or generate validator keys.

## Start and inspect a local RPC node

An RPC index snapshot produced by an Actum operator is required. The plugin never creates,
rewrites, or deletes that snapshot.

```sh
scripts/actum-node start --snapshot /path/to/rpc-index.snapshot --bind 127.0.0.1:49151
scripts/actum-node status
scripts/actum-node query --address 127.0.0.1:49151
scripts/actum-node logs --lines 100
scripts/actum-node stop
```

`start` owns only the process recorded under `PLUGIN_DATA`. It strips inherited
`ACTIVECHAIN_*` variables, preventing ambient faucet, wallet-ingress, anchor, or signing settings
from silently widening the node. Do not bind a development RPC node to a public interface.

## Query another node

`query` does not require a locally managed process:

```sh
scripts/actum-node query --address rpc.example.test:49151
```

Report the returned chain ID, immutable genesis commitment, protocol and RPC schema revisions,
finalized height, and health. Treat mismatched identity, stale health, connection failure, or
non-canonical responses as failure. Use the repository's pinned `probe-kanalen-rpc.py` for the
public Kanalen TLS endpoint because that probe additionally pins its expected network identity.

## MCP boundary

The packaged MCP server is developmental. Its current executable provides protocol discovery and
bounded request handling, but its backend is not connected to a live RPC store. Do not claim its
read-only tools are operational when they return `unavailable`, and never treat MCP proposals as
signing authority. Transfers still require canonical native-wallet review.

## Safety rules

- Never kill a process when the recorded executable, command, or start time does not match.
- Never delete snapshots, chain state, wallets, seeds, or keys.
- Never pass secrets on a command line or add credentials to `mcp.json`.
- Ask for explicit operator approval before changing public listeners, firewall rules, or services.
- Use `stop` before replacing binaries or snapshots used by a plugin-owned process.
