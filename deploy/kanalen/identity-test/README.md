# EUWallet in-app test connection (#846)

This receiver exercises real signed OpenID4VP requests, EUWallet's consent and holder signing,
and an HTTPS `direct_post` back to ActiveChain. It accepts **only EUWallet sample PID credentials**
from the deliberately public test issuer key. It emits `test_only` receipt metadata, never native
admission evidence, verified government identity, or an on-chain identity registration.

The fixture files are copied unchanged from `advatar/EUWallet`, revision
`8b1bf2f82340c8fba6641b5cc6baa1d9e18b3f3c`, `crates/x509/tests/vectors/rp.der` and
`rp.pkcs8.der`. This private key is a PUBLIC TEST FIXTURE, not a deployment secret.
Do not use it for any production trust or value-bearing authorization.

## Test in the apps

1. Install the Debug EUWallet build from `feat/195-activechain-presentation-trust` and the
   ActiveChain build from this issue branch on the same iOS simulator/device.
2. In EUWallet, open Settings, enable **Test connection**, and choose **Add sample PID for
   ActiveChain**. Approve **Add document**, then **Go to Wallet**. The existing sample issuer's
   copy is part of EUWallet's demo; this is not an issued government document.
3. In ActiveChain, create/load a Kanalen wallet and select **Identity → Use EUWallet**.
4. If iOS asks whether ActiveChain may open EUWallet, choose **Open**. Review the age-over-18 disclosure in EUWallet and approve. ActiveChain receives a token-only
   return link, then independently fetches the authenticated session result. A redirect by itself
   never attaches a credential. **Check result** also works if automatic return fails.
5. The attached item is labeled **Test credential**, and its metadata persists in this device's
   keychain, scoped to the wallet and genesis. No personal claims or holder private key are stored
   in ActiveChain. External issuer trust/status and on-chain identity enrollment remain deferred.

The EUWallet test resolver is compiled only in Debug builds, requires explicit opt-in, compares
request certificates with the exact existing bootstrap test certificate, and permits only
`https://kanalen.actum.network/identity-test/response`. Release builds retain signed-registration
requirements. Requests expire after five real minutes; the credential proof uses EUWallet's fixed
sample clock, explicitly separate from real session expiry.

## Receiver

Install Python dependencies with `pip install -r requirements.txt`; run
`python receiver.py --database /private/path/sessions.sqlite`. Run `install.sh` on the Kanalen
host for a detached development receiver on port 49159, then install the repository's managed
Caddy fragment. This development process must be started again after a host restart; it is
separate from validator services. Its session database contains wallet bindings, hashed polling
tokens and proof hashes, not credential bytes or claim values. Success/decline/rejection consumes
one session durably. Polling requires the private token. Capacity is bounded to 512 sessions;
records are retired after expiry plus one day. Do not add HTTP access logging of request bodies
or Authorization headers.

Run `python -m unittest discover -s deploy/kanalen/identity-test -p test_receiver.py` from the
repository root. Run Swift `IdentityTestSessionTests` for callback and receipt substitution checks.
The targeted `EUWalletConnectionUITests` uses the installed EUWallet app, sample credential
issuance, live HTTPS receiver, consent, attachment and relaunch. Its payment stability test needs
an already-finalized demo purchase; neither test spends funds or resets an existing wallet.

The dedicated `ActiveChainWalletIdentityE2E` scheme contains these two contextual checks; the
fresh-wallet/faucet scheme does not run them. For an already-funded simulator with EUWallet installed:

```sh
xcodebuild -project mobile/ios/ActiveChainWalletApp/ActiveChainWallet.xcodeproj \
  -scheme ActiveChainWalletIdentityE2E -destination "platform=iOS Simulator,id=$SIMULATOR_ID" \
  -parallel-testing-enabled NO -maximum-concurrent-test-simulator-destinations 1 \
  CODE_SIGNING_ALLOWED=YES CODE_SIGN_IDENTITY=- test
```
