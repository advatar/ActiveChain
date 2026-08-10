# Kanalen public RPC gateway

This edge proxy shares public TCP port 443 with the Mac's existing HTTPS Caddy service.
Traefik selects `rpc.kanalen.activechain.dev` by TLS SNI, terminates TLS 1.3 with an
automatically renewed Let's Encrypt certificate, and forwards the decrypted ActiveChain framed
TCP stream to `host.lima.internal:49151`.

All other SNI names pass through unchanged to `providehr-caddy:443`. The existing Caddy container
must therefore stay on the external `providehr_default` Docker network and must not publish host
port 443 while this gateway is active. Its host mapping is `8443:443` for rollback diagnostics;
host port 80 remains with Caddy for its existing HTTP sites.

The gateway does not expose consensus (`49150`), faucet (`49152`), or metrics (`49153`).
The companion `kanalen.Caddyfile` fragment gives `kanalen.activechain.dev` a TLS-backed
developmental-status response through the existing Caddy service.

The Kanalen host runs validator followers on loopback ports `49154` and `49155`. The
`dev.activechain.kanalen.round` LaunchAgent proposes a PQ-authenticated quorum round every 30
seconds on `49150`, persists validator snapshots, and ingests the resulting monotonic finalized
height into the RPC index. `activechain-rpc-node` reloads that durable index for every accepted
connection, so no RPC restart is required after ingestion.

Deploy only after validating the current Caddy configuration and taking backups:

```sh
mkdir -p "$HOME/activechain-deploy/kanalen/gateway/letsencrypt"
chmod 700 "$HOME/activechain-deploy/kanalen/gateway/letsencrypt"
docker compose -f "$HOME/activechain-deploy/kanalen/gateway/compose.yml" config
docker compose -f "$HOME/activechain-deploy/kanalen/gateway/compose.yml" up -d
```

Rollback by stopping this compose project and restoring the existing Caddy `443:443` host
mapping from its timestamped backup.

The public funding method is carried on the TLS-fronted RPC service at `49151`; port `49152`
is not a separate public faucet. Do not enable `ACTIVECHAIN_FAUCET_ENABLED` until the wallet-ingress
snapshot, finalized treasury authorization lane, permission-restricted operator seed, settlement
journal, limits, and expiry described in `docs/FAUCET_FUNDING_ADMISSION_V2.md` are provisioned.
The public wallet submits `RequestFaucet`; it must never receive the treasury seed or be required
to construct a treasury-signed cash transfer.

## Telemetry anchor gateway

`anchor.kanalen.activechain.dev` terminates TLS at Traefik and forwards HTTP only to the private
`activechain-telemetry-anchor-gateway` listener on `127.0.0.1:49156`. Provision DNS before enabling
the route. The RPC LaunchAgent enables its durable anchor registry at
`rpc/anchors.snapshot`; finalization remains an operator-only `activechain-anchor-admin` action.

Before loading `dev.activechain.kanalen.anchor`, create the private state and a high-entropy bearer
token without printing it:

```sh
install -d -m 700 "$HOME/activechain-deploy/kanalen/anchor"
umask 077
openssl rand -base64 48 > "$HOME/activechain-deploy/kanalen/anchor/bearer.token"
chmod 600 "$HOME/activechain-deploy/kanalen/anchor/bearer.token"
```

The idempotency journal is created mode 0600 on first accepted request. Configure
`ACTUM_ANCHOR_URL=https://anchor.kanalen.activechain.dev/v1/anchors` and provide the same protected
token to the trusted application/plugin deployment. Never place the bearer in telemetry, logs,
proof inputs, browser code, repository secrets, or command-line arguments.

The authenticated `GET /v1/health` endpoint returns healthy only when the finalized RPC view is
fresh and the native anchor registry, operator fee account, nonce channel, and empty proposal spool
are all ready to accept a new submission. Operators must alert on any non-200 response.
