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

Deploy only after validating the current Caddy configuration and taking backups:

```sh
mkdir -p /Volumes/ActiveChain/testnet/gateway/letsencrypt
chmod 700 /Volumes/ActiveChain/testnet/gateway/letsencrypt
docker compose -f /Volumes/ActiveChain/testnet/gateway/compose.yml config
docker compose -f /Volumes/ActiveChain/testnet/gateway/compose.yml up -d
```

Rollback by stopping this compose project and restoring the existing Caddy `443:443` host
mapping from its timestamped backup.
