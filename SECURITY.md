# Security policy

## Supported versions

Only the latest tagged release gets fixes. `@v1` is a moving major tag that always points at the newest `v1.x.y`; pin to a specific tag or commit SHA in your own workflow if you need a fix to land on your schedule rather than the moment it's tagged.

## Reporting a vulnerability

This action runs inside your CI pipeline with whatever permissions your workflow grants it, so a vulnerability here is a supply-chain concern for every repo that consumes it.

- Use GitHub's [private security advisories](https://github.com/jimy-r/redaction-check-action/security/advisories/new) — not a public Issue.
- Include the affected version or commit, and a minimal repro if you have one.

Do not open a public Issue for a suspected vulnerability. The report should reach a maintainer before it's discoverable by anyone who'd exploit it.

## Out of scope

- A pattern the action fails to catch is a detection gap, not a vulnerability. File it as a regular Issue with the shape it missed (redacted, not the real value).
- Vulnerabilities in the actions this composite action depends on (`actions/checkout`, `actions/setup-python`): report upstream.

## Maintainer response

Private security advisories get a first response within a week. If you don't hear back in two weeks, open a new private advisory as a ping.

---

*Last verified against the repo structure on **2026-08-28**.*
