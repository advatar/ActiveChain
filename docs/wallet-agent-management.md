# Wallet agent management

An ActiveChain agent is an independently authenticated principal that receives one or more
attenuated capabilities. It is not synonymous with an installed application. The wallet manages
the authority that an agent can exercise through ActiveChain; it does not claim ownership of the
agent process or visibility into everything that process does.

## Enforcement model

Every agent request must bind the agent principal, capability, action, exact resource or recipient,
amount and fee or disclosed claims, chain, nonce, and expiry. Enforcement is layered:

1. The wallet registry rejects unknown, paused, expired, over-budget, missing-capability, replayed,
   revocation-pending, and revoked agents before approval or signing.
2. A human-approval policy may require biometrics for the exact canonical request.
3. The secure-key callback signs only that canonical request; wallet key material is never shared
   with the agent.
4. Validator authorization verifies the principal, capability chain, policy, budgets, revocation,
   nonce, and request binding again.

Pause is local and immediate. Revocation is also fail-closed locally as soon as it is submitted, but
the UI distinguishes `revocation pending` from a revocation proven in finalized chain state. This
prevents another wallet instance from treating a merely local toggle as global revocation.

The durable registry stores public principals, capability identifiers, policy limits, lifecycle
state, and consumed request identifiers. It stores neither wallet nor agent secret keys.

## Process and application shapes

### Wallet-owned apps and extensions

A wallet-owned Safari extension, share extension, App Clip, or companion app may use an Apple App
Group as a bounded request and receipt inbox. App Groups are available only to apps and extensions
produced by the same developer team. The group must never contain signing keys, bearer
capabilities, unencrypted credentials, or an authorization result that can be replayed.

The inbox is a transport convenience, not an authorization boundary. Every message still requires
canonical validation, agent authentication, nonce checking, and wallet/chain policy evaluation.

Apple documents that App Groups share containers among apps from the same development team:
<https://developer.apple.com/documentation/xcode/configuring-app-groups>.

### Third-party apps

A third-party application cannot join the wallet's App Group and cannot read the wallet container.
It integrates as a protocol client:

- locally through a universal link, QR code, document/import handoff, or explicit callback;
- through a browser extension request;
- or remotely through a relay carrying an authenticated, encrypted request.

The user sees the third party's verified principal, requested capability, exact effects, limits,
and expiry. Approval returns only a scoped response or receipt. A third-party app never receives a
wallet key or ambient permission to request arbitrary signatures.

The wallet can pause or revoke that app's ActiveChain capabilities. It cannot intercept the app's
unrelated filesystem access, UI, local computation, conventional web accounts, or transactions
performed outside ActiveChain. iOS app sandboxing is the reason this must be an explicit protocol
rather than hidden cross-app inspection.

### Remote agents

A cloud or desktop agent follows the same principal/capability protocol. Push notification may
alert the wallet, but the notification is not authorization. The wallet fetches or receives the
bounded encrypted request, verifies it, and returns a request-bound receipt. Remote agents should
normally receive shorter expiry and smaller budgets than local wallet-owned components.

### Managed-device controls and network extensions

Apple Network Extension content filters can allow or deny network flows created by other apps, and
VPN providers can route traffic. These require the appropriate entitlement, explicit configuration,
strict privacy handling, and App Review compliance. A network provider observes flows, not the
semantic intent of an encrypted third-party protocol, and it cannot prove that an app performed an
ActiveChain action. It therefore must not become the wallet authorization root.

Apple describes on-device content filters and their privacy-separated providers at
<https://developer.apple.com/documentation/networkextension/content-filter-providers>, and the
Network Extension entitlement at
<https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension>.
The App Review Guidelines additionally constrain VPN distribution and data use:
<https://developer.apple.com/app-store/review/guidelines/#vpn-apps>.

Screen Time's Family Controls, Managed Settings, and Device Activity APIs are designed for
user/guardian-authorized usage controls. They are not a general wallet surveillance API. Managed
enterprise devices can apply stronger MDM policies, but that is a separate deployment product and
does not expand an ActiveChain capability.

## Product behavior

The wallet agent inventory must show:

- verified agent principal and human-readable label;
- connection kind: wallet-owned, third-party, remote, or managed-device extension;
- granted capabilities and remaining budget;
- expiry and last request;
- active, paused, revocation-pending, expired, or finalized-revoked state;
- whether requests require human approval;
- a request history linked to finalized receipts.

Pause/resume is appropriate for temporary control. Revoke is permanent for the named capability
grant and requires a new attenuated grant to restore authority. Removing an app from the phone does
not revoke a remote capability; uninstall detection must never substitute for on-chain revocation.

## Siri, Shortcuts, and App Intents

App Intents are invocation and navigation surfaces, not agent credentials. The iOS wallet exposes
authenticated shortcuts to open agent management and pending approvals. These intents require
device authentication and then open the wallet. They do not grant, expand, approve, revoke, sign,
or submit authority-changing operations without the wallet's exact review flow.

The system invocation identity must never be interpreted as an ActiveChain principal. The canonical
agent command, wallet policy, secure signing callback, and validator authorization remain mandatory
after an App Intent runs. Apple documents App Intents as actions discoverable by Siri, Shortcuts,
Spotlight, widgets, and Apple Intelligence:
<https://developer.apple.com/documentation/appintents>.
