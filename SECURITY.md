# Security policy

## Developmental status

ActiveChain has not completed an independent security audit and has no production-ready release.
Do not use the software to protect real value or sensitive production workloads. The audit scope
and launch gate are documented in [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md).

## Report a vulnerability privately

Do **not** open a public issue, discussion, or pull request for a suspected unpatched vulnerability.
Use GitHub's private vulnerability reporting flow:

<https://github.com/advatar/ActiveChain/security/advisories/new>

Include, where possible:

- affected commit, component, protocol version, and configuration;
- impact and the security property that fails;
- minimal reproduction steps or a proof of concept;
- whether exploitation requires keys, network position, timing, or unusual resources;
- suggested mitigations and any disclosure constraints.

Do not include real user secrets, production credentials, or unnecessary personal data.

## Response process

Maintainers will acknowledge a usable report as soon as practical, reproduce and triage it, agree
on a coordinated disclosure plan with the reporter, and publish remediation information after a fix
is available. Response times are best-effort while the project is developmental; no paid bug bounty
or guaranteed service-level agreement currently exists.

Good-faith research that avoids privacy violations, data destruction, service disruption, social
engineering, and access beyond what is needed to demonstrate the issue is welcome. This statement
is not legal authorization to test systems or data you do not own or have permission to assess.

## Supported versions

Only the latest commit on `main` is currently maintained. There are no supported stable release
branches. Testnet configurations and stored state may be reset or migrated without backward
compatibility while their documents label them developmental.

## Security boundaries

Tests, formal models, deterministic vectors, and transparent proofs cover bounded properties only.
They do not replace review of integration, key custody, side channels, networking, deployment,
operations, dependencies, or human approval flows. Never infer a production assurance claim from a
component test or proof without checking its published scope.
