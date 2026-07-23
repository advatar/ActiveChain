# ActiveChain PQ testnet operations

This runbook describes the deterministic local rehearsal used before opening a
public testnet slot. Every validator must use the same genesis manifest and a
distinct validator index.

## Generate a manifest

```sh
cargo run --release -p activechain-consensus-runtime --bin genesis-tool -- \
  ./testnet/genesis.bin 1 1 3
```

The manifest binds epoch, activation height, stake, validator IDs, and ML-DSA-44
public keys. Keep it immutable after distribution.

## Derive an operator wallet

```sh
cargo run --release -p activechain-wallet-core --bin activechain-wallet -- \
  derive 0 1 0
```

Register the printed principal in the testnet faucet manifest. Never reuse a seed or principal
between testnet genesis files.

## Fund and submit a transfer

The faucet issues a test-only Coin Cell on the exact genesis chain. The wallet must discover a
funded cell, reserve a distinct fee cell, construct a canonical `CoinTransfer`, wrap it in a
chain/sender/nonce/session-bound `CashAuthorizationRequestV1`, sign the exact canonical transcript
with ML-DSA-44, and submit the outer `AuthorizedCashTransferV1` envelope. Ingress resolves the
sender key from finalized state and atomically applies the cash transition while consuming the
nonce, session, payment inputs, and fee input. Bare transfers are test helpers only and MUST NOT be
accepted by a network handler.

## Run the process rehearsal

```sh
bash scripts/rehearse-validator-processes.sh
```

## Build and deploy the Kanalen bundle

The manually triggered `Kanalen testnet deployment` workflow builds pinned release binaries and
publishes a checksum. During the home-network phase, set its deploy host to `192.168.2.126` and
enable deployment. The workflow requires `KANALEN_DEPLOY_USER` and `KANALEN_DEPLOY_KEY` secrets,
copies the bundle to `/Volumes/ActiveChain/testnet/`, and never exposes validator peer ports.

Kanalen reserves the host port block `49150-49153` to avoid the Mac mini's existing services:

- `49150` validator consensus peer listener;
- `49151` public RPC gateway;
- `49152` faucet HTTP service;
- `49153` metrics/health endpoint.

Only `49151-49153` should be reverse-proxied later. Keep `49150` restricted to validator peers.

The rehearsal must produce one persisted snapshot per validator and report
`proposals=1 votes=1 rejected=0` for every process. A rejected-message count
greater than zero is a release blocker.

## Operator gates

Run the complete local wallet acceptance path before publishing any deployment:

```sh
scripts/rehearse-testnet-wallet-acceptance.sh
```

The rehearsal generates a three-validator genesis, derives an operator wallet, issues a
genesis-bound faucet grant, admits a signed funded transfer, proves replay rejection, finalizes
through three authenticated processes, and restarts each validator from durable state.

- Do not admit a validator whose genesis public key does not match its derived
  signer.
- Do not accept consensus frames before the ML-DSA peer handshake succeeds.
- Stop rollout if any validator reports rejected messages, divergent genesis
  roots, or a snapshot that cannot be loaded after restart.
- A testnet announcement requires a green self-hosted CI run and successful
  partition, replay, late-vote, restart, and sustained-load rehearsals.
- Public faucet and transaction-ingress endpoints may only be announced with the signed genesis
  manifest; placeholder endpoints are not launch infrastructure.

Metrics exposed by `ValidatorService::metrics()` are intentionally monotonic:
`proposals`, `votes`, `finalized_certificates`, and `rejected_messages`.

## Public DNS and TLS

DNS only names a reachable gateway; it does not make a private Mac mini reachable. First assign a
stable public IPv4/IPv6 address to the gateway, or place a small public relay in front of the home
network with a WireGuard tunnel. Do not publish the Mac mini's private `192.168.2.126` address.

For a zone such as `example.org`, create:

| Record | Name | Value | Purpose |
| --- | --- | --- | --- |
| `A` | `rpc.kanalen` | public gateway IPv4 | TLS-wrapped ActiveChain RPC |
| `AAAA` | `rpc.kanalen` | public gateway IPv6 | optional native IPv6 RPC |
| `CAA` | `@` | `0 issue "letsencrypt.org"` | restrict certificate issuance, if Let's Encrypt is used |

Use a low TTL such as 300 seconds during rollout, then raise it after the address is stable.
Configure the resulting client endpoint as `rpc.kanalen.example.org:443`. Keep the record
**DNS-only** at providers whose ordinary proxy supports HTTP but not arbitrary TCP. The
ActiveChain RPC protocol is bounded framed TCP, not HTTP; Cloudflare's normal orange-cloud proxy,
for example, is not a compatible transport. A raw-TCP product such as Spectrum or an operator-owned
layer-4 relay is required if proxying is desired.

Terminate TLS at a layer-4 gateway and proxy only to loopback/VPN port `49151`. An nginx build with
the stream module can use:

```nginx
stream {
    upstream activechain_rpc {
        server 127.0.0.1:49151;
    }

    server {
        listen 443 ssl;
        listen [::]:443 ssl;
        proxy_pass activechain_rpc;
        proxy_timeout 10s;
        ssl_certificate /etc/letsencrypt/live/rpc.kanalen.example.org/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/rpc.kanalen.example.org/privkey.pem;
        ssl_protocols TLSv1.3;
    }
}
```

Forward public TCP `443` to that gateway only. Bind `activechain-rpc-node` to
`127.0.0.1:49151` when the gateway is local, or to its WireGuard address when relayed. Do not
forward consensus port `49150`; validator peers must use an allowlisted VPN/firewall path.

Do not create public `faucet` or `status` records yet. The checked-in faucet is currently an
operator CLI rather than an HTTP service, and validator metrics are an in-process API rather than
a hardened public endpoint. Publishing names before those authenticated/rate-limited services
exist would create misleading launch infrastructure. Once implemented, use separate
`faucet.kanalen` and `status.kanalen` names terminating HTTPS on `443`, internally routed to
`49152` and `49153`; never expose those high ports directly.

Before announcing the record:

1. verify the authoritative answer with `dig +short rpc.kanalen.example.org A` and `AAAA`;
2. verify the certificate name and TLS 1.3 handshake from outside the home network;
3. run an encoded RPC status request through the public endpoint and verify chain ID, genesis,
   protocol revision, finality height, and staleness;
4. confirm `49150`, `49152`, and `49153` are unreachable from the public Internet; and
5. repeat the finality query after restarting the RPC process and one validator.
