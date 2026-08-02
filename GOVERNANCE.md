# Governance

ActiveChain currently uses a maintainer-led open-source governance model.

## Decisions

- Routine changes are proposed through issues and pull requests and accepted by repository
  maintainers after review and required verification.
- Protocol changes require a versioned specification or an explicit update to one, plus analysis of
  compatibility, migration, security, privacy, determinism, resource bounds, and independent-client
  impact.
- Security-sensitive changes may be developed privately until coordinated disclosure is safe.
- Maintainers may reject changes that pass tests but weaken a documented invariant or exceed the
  review and complexity budget.

Discussion aims for reasoned consensus. When consensus is unavailable, maintainers decide based on
the published system goals, evidence, and long-term maintenance burden, and should record material
tradeoffs in the issue or specification.

## Roles

- **Contributors** propose issues, code, documentation, tests, specifications, or review.
- **Reviewers** evaluate changes within their expertise and identify unproven claims or risks.
- **Maintainers** merge changes, manage releases and infrastructure, coordinate security response,
  and enforce repository policies.

Roles are based on sustained, constructive contribution and judgment. No token, credential,
validator stake, repository activity count, or testnet role currently grants repository governance
rights.

## Releases and protocol governance

The repository does not yet publish a production network release. A merge to `main`, testnet
deployment, roadmap checkbox, or protocol draft is not a governance vote for a future production
network. Production upgrade and network governance must be specified, independently reviewed, and
adopted separately before launch.

## Conduct and conflicts

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Reviewers and maintainers
should disclose financial, employment, audit, vendor, or research conflicts relevant to a decision.
