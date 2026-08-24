# Kanalen integrator onboarding v1

Status: developmental integration guide for the Kanalen testnet. Kanalen and its wallet have not
completed an independent security audit. Do not use production keys or value you are unwilling to
lose.

This guide describes the public network deployed from source revision
`412b8e70c564872532bb9c83ada453ff04ea9d80`. It gives an integrator the exact network pins,
read-only liveness procedure, wallet/faucet path, RPC constraints, and current limitations without
requiring private operator access.

## Current readiness

| Surface | Current state |
|---|---|
| Public RPC | Live as raw canonical frames inside TLS 1.3 at `rpc.kanalen.actum.network:443` |
| Network status | Public and unmetered; exact chain, genesis, protocol, and schema checks required |
| RPC access | `Free` on the deployed node; no access grant is currently required |
| Apple reference wallet | Builds from source; creates a network-scoped key, requests funding, and verifies owner Coin Cells |
| Faucet | Testnet-only; one complete grant delivers two Coin Cells whose amounts sum to the advertised grant amount |
| Ordinary live transfer | Not exposed by the reference app or public RPC yet; see [Spending boundary](#spending-boundary) |
| Android reference wallet | Status-only for this workflow; funding, verified balance, and transfers remain unavailable |
| Signed wallet download | Not published; the Apple archive produced by the repository script is an unsigned development artifact |

The last three rows are product boundaries, not troubleshooting failures. In particular, two
funded Coin Cells make a transfer constructible because one can be the payment input and the other
the distinct fee reserve. They do not themselves provide a public submission endpoint.

## Immutable network card

Pin these values from this guide or another authenticated release channel before connecting. A
client must compare the peer's `Status` response with the pins; it must never learn a network
identity from a peer and then trust that same response as the authority for the identity.

| Field | Required value |
|---|---|
| Network | Kanalen |
| TLS server name | `rpc.kanalen.actum.network` |
| Port | `443` |
| Chain ID | `b12c1c316717e9669cec36f7632a9080702c57a3125d90c72154f8a7298e4f0b095e6cfe944bd2c9f6535b4c927782f1` |
| Genesis commitment | `a836c4d201cda6ba33a01aa48011cf5f4d6acdfd1ec409d322dc1b56ed3552a25dcb158e0b1ec0352728653d315d477c` |
| Protocol revision | `1` |
| RPC schema revision | `3` |
| Deployed source revision | `412b8e70c564872532bb9c83ada453ff04ea9d80` |

Chain ID and genesis are separate 48-byte values. A future binary release may change while these
network pins remain stable. A genesis replacement is a different chain for wallet-authority
purposes and requires an explicit new pin.

## Verify TLS and canonical status

The endpoint is not HTTP, WebSocket, JSON-RPC, or gRPC. `curl` is therefore the wrong liveness
probe. TLS is selected by SNI and carries ActiveChain's four-byte-length-prefixed canonical RPC
frames after the handshake.

First verify that the certificate is valid for the exact host:

```sh
openssl s_client \
  -connect rpc.kanalen.actum.network:443 \
  -servername rpc.kanalen.actum.network \
  -tls1_3 </dev/null 2>/dev/null |
  openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

The repository's Rust probe speaks the canonical protocol over a plain TCP stream. For the public
edge, put it behind a locally bound, certificate-verifying TLS tunnel. This example uses Ncat from
Nmap (`brew install nmap` on macOS) and macOS's system CA bundle; set `TLS_CA_FILE` to the system
bundle on another platform.

```sh
git clone --recurse-submodules https://github.com/advatar/ActiveChain.git
cd ActiveChain
git checkout --detach 412b8e70c564872532bb9c83ada453ff04ea9d80

cargo build --locked -p activechain-rpc-server --bin activechain-rpc-probe

export KANALEN_HOST=rpc.kanalen.actum.network
export TLS_CA_FILE=/etc/ssl/cert.pem
ncat -lk 127.0.0.1 49191 --sh-exec \
  'ncat --ssl --ssl-verify --ssl-servername "$KANALEN_HOST" \
    --ssl-trustfile "$TLS_CA_FILE" "$KANALEN_HOST" 443' &
tls_proxy_pid=$!
trap 'kill "$tls_proxy_pid" 2>/dev/null || true' EXIT

target/debug/activechain-rpc-probe 127.0.0.1:49191
```

The height changes continually, but a compatible healthy response has this shape:

```text
chain_id=b12c...82f1 genesis=a836...477c protocol_revision=1 \
rpc_schema_revision=3 finalized_height=<advancing-height> health=Healthy
```

Treat any chain, genesis, protocol, or schema mismatch as incompatible. Do not downgrade a client
or replace its stored pin from the returned value. `Stale` is a valid status response but blocks
proof queries until finality becomes fresh again.

`Status` and `AnchorServiceStatus` are deliberately available without an RPC access grant in every
access mode. The deployed node currently omits an access-terms argument and therefore runs in
`Free` mode. Free transport does not make responses trusted: clients still verify finality and
record proofs.

## Build and run the Apple development wallet

There is no signed public wallet download yet. The supported reference path builds the exact
deployed source on macOS 14 or later with Xcode, XcodeGen, the pinned Rust toolchain, and these Rust
targets:

```sh
rustup target add \
  aarch64-apple-darwin \
  x86_64-apple-darwin \
  aarch64-apple-ios \
  aarch64-apple-ios-sim
brew install xcodegen

scripts/build-macos-wallet-app.sh
```

The script requires a clean checkout and writes an unsigned archive to:

```text
target/apple-archives/ActiveChainWalletMac-412b8e70c564872532bb9c83ada453ff04ea9d80.xcarchive
```

For an interactive development run, open
`mobile/ios/ActiveChainWalletApp/ActiveChainWallet.xcodeproj`, select the
`ActiveChainWalletMac` scheme, configure a development team and unique bundle identifier that you
control if necessary, and run it from Xcode. Do not bypass platform security to treat the unsigned
archive as a release application.

The built-in `Kanalen` entry already contains the immutable card above. Network selection is a
user choice and remains a pin: selecting a network changes the expected host and identity; the
node cannot select itself. Wallet keys and profiles are stored separately per network.

## Create and fund a wallet

1. Confirm that the Network card shows `Kanalen`, `Healthy`, and an advancing finalized block.
2. Select **Create wallet**. The app creates an ML-DSA-44 seed wrapped through the platform
   custody provider and binds its profile to the selected genesis.
3. Save the displayed recovery key before selecting **I have saved it**. It is shown once. The
   Secure Enclave wrapping key is device-bound; the recovery key is what permits re-wrapping on a
   replacement device.
4. Select **Request testnet funding** once the funding card is ready.
5. Leave a `Pending` request pending and refresh normally. Pending or rejected receipts never
   change the displayed balance. A grant becomes complete only after both of its Coin Cell
   transfers finalize.
6. Accept the balance only when the app reports a verified owner-scoped Coin Cell page at a named
   finalized height. `Unavailable`, `Unverified`, and a verified empty page are different states.

The app currently displays the number of verified Coin Cells, not an aggregated ACT amount. It
cryptographically binds each accepted record to the requested owner, cash root, finalized height,
validator certificate, and pinned genesis.

### Current faucet policy

Clients should fetch `FaucetTerms` before every request rather than permanently compiling these
operator limits. The deployment at the revision above currently uses:

| Policy | Current value |
|---|---|
| Total amount per complete grant | `100000000000000000000` atomic units |
| Coin Cells per complete grant | `2`, split so their amounts sum to the advertised total |
| Recipient cooldown | `86400` seconds |
| Recipient lifetime limit | `3` complete grants |
| Source window | `3600` seconds |
| Source limit | `5` complete grants per window |
| Global window | `3600` seconds |
| Global limit | `100` complete grants per window |
| Challenge | cooldown-only; no proof-of-work challenge currently configured |

Source limiting uses a server-derived peer identity. Several developers behind one NAT may share
the five-per-hour allowance. An incomplete grant remains recoverable and consumes no recipient
allowance until every required cell has settled; do not create new identities or idempotency keys
to work around a pending reservation.

## Spending boundary

An ordinary cash transfer needs at least one payment input and a distinct fee-reserve Coin Cell.
The two-cell faucet policy removes the former one-cell dead end. The production admission shape is
still a canonical, ML-DSA-44-signed `AuthorizedCashTransferV1` bound to the chain, sender, nonce,
one-shot session, exact inputs, recipient, amount, fee, and validity height. No network endpoint
accepts a private key, an unsigned transfer, or a `send amount` shortcut.

The current public integration stops before live ordinary-transfer submission:

- the Apple reference app intentionally displays **Transfers disabled** and does not construct or
  submit an ordinary transfer;
- Android does not yet expose funding, verified balance, or transfer operations; and
- RPC schema revision 3 has faucet and anchor submission requests but no general
  `SubmitAuthorizedCashTransfer` request.

Integrators can exercise the complete local signing/admission/finality/replay/restart boundary:

```sh
bash scripts/rehearse-testnet-wallet-acceptance.sh
```

That rehearsal is not a way to submit value to live Kanalen. Track 0's stronger condition that an
outside developer can install a published wallet and spend unaided remains open until a reviewed
distribution and public ordinary-transfer path are available.

## Independent RPC client checklist

Use `activechain-rpc-types` for bounded wire types and `activechain-verifier-api` or an independently
qualified equivalent for proof verification. A client implementation must:

1. validate the TLS certificate for `rpc.kanalen.actum.network` with SNI;
2. send and receive exactly one four-byte big-endian length prefix plus one canonical envelope;
3. reject zero-length or larger-than-4-MiB frames, non-minimal lengths, wrong type/schema tags,
   trailing bytes, and unknown variants;
4. encode `RpcRequest` with type tag `0x0107`, schema `2`, and decode `RpcResponse` with type tag
   `0x010A`, schema `3`;
5. compare `Status` with every immutable network-card value before other queries;
6. accept only advertised, implemented proof kinds and verify the complete finalized evidence;
7. paginate list queries with the last returned key as the exclusive cursor and request at most
   four records per page; and
8. distinguish unreachable, stale, not-found, verified-empty, and invalid-proof results.

The server applies two-second read/write deadlines. Clients may use a slightly longer end-to-end
timeout for DNS and TLS, but retries must preserve request idempotency and must never turn an
unknown value-changing outcome into a second authorization.

## Troubleshooting

| Symptom | Meaning and response |
|---|---|
| HTTP error, empty `curl` output, or binary output | The RPC endpoint is not HTTP; use a canonical framed client over TLS. |
| TLS certificate mismatch | Connect by the exact hostname with SNI; do not pin or use a bare IP address. |
| Peer closes immediately after a request | Check the request type tag and schema. The deployed request envelope is schema 2, not schema 1. |
| Wallet shows `Incompatible` | At least one chain, genesis, protocol, or RPC schema pin differs. Fail closed. |
| Wallet shows `Stale` | Status is reachable but finality is too old; wait for advancement before proof/funding operations. |
| Funding is unavailable | A healthy checkpoint and a wallet profile for the selected network are both required. |
| Faucet reports cooldown/source/global limit | Respect the returned wait interval; remember that office/NAT users may share a source limit. |
| Faucet remains pending | Refresh and retain the original request/reference. A two-cell grant may be partially settled and recoverable. |
| Balance is unavailable or unverified | Do not display zero or credit funds. Only a verified owner page is balance evidence. |
| Transfer controls are disabled | This is the current reference-client/public-RPC boundary, not a funding failure. |

## Source map

- [`mobile/ios/ActiveChainWalletApp/Sources/WalletNetwork.swift`](../mobile/ios/ActiveChainWalletApp/Sources/WalletNetwork.swift)
  — built-in network card and per-network storage isolation.
- [`mobile/ios/ActiveChainWalletApp/Sources/WalletLiveState.swift`](../mobile/ios/ActiveChainWalletApp/Sources/WalletLiveState.swift)
  — TLS transport, status/faucet codecs, funding lifecycle, and verified owner pages.
- [`deploy/networks/kanalen.json`](../deploy/networks/kanalen.json) — deployment policy values.
- [`deploy/kanalen/gateway/README.md`](../deploy/kanalen/gateway/README.md) — public TLS/SNI edge.
- [`FAUCET_FUNDING_ADMISSION_V2.md`](FAUCET_FUNDING_ADMISSION_V2.md) — faucet authorization and
  finality boundary.
- [`implementation/devnet-rpc.md`](implementation/devnet-rpc.md) — canonical RPC framing and
  proof-query contract.
- [`implementation/rpc-access-economics.md`](implementation/rpc-access-economics.md) — free,
  allow-list, and prepaid access behavior.
- [`testnet-operations.md`](testnet-operations.md) — operator-side release and recovery runbook.
- [`TESTNET_RELEASE.md`](TESTNET_RELEASE.md) — developmental release gates and limitations.
