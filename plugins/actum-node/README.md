# Actum node Agent Plugin

This directory is an [Agent Plugins v1.0.0](https://agent-plugins.org) package. Install this
directory with a compatible client. The client supplies `PLUGIN_ROOT` and a persistent,
client-owned `PLUGIN_DATA` directory.

It also includes `.codex-plugin/plugin.json` and `.mcp.json` for direct Codex discovery. The
Codex manifest references the same portable `skills/` directory and bounded MCP launcher.

The portable package provides:

- the `actum-node` skill for building, starting, stopping, inspecting, and querying an RPC node;
- a portable stdio entry for the existing bounded ActiveChain MCP server;
- process ownership checks, loopback-only local binding, bounded log reads, and ambient feature
  scrubbing.

The package does not include binaries. Run the skill's `build` command in an ActiveChain source
checkout, then set `ACTUM_BIN_DIR` to that checkout's `target/release` directory if it is not on
`PATH`. The MCP server remains developmental and does not yet connect its tools to a live store.

This plugin does not create validators, custody keys, reset state, expose public listeners, or
grant an agent signing authority.
