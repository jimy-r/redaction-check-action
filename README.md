# redaction-check-action

A composite GitHub Action that scans a pull request's added lines for the shapes of private content before they merge. It looks for email addresses, absolute home paths, credential and token prefixes, private-IP and hostname shapes, and filenames that are almost always meant to stay untracked.

It works entirely off the diff, against the *shape* a leak tends to take rather than a live denylist of real secrets (this is a public action, so it can't ship one). That keeps it fast and dependency-free, and it keeps the gate honest about its own scope. Catching common-shaped mistakes is not the same as guaranteeing privacy.

## What it catches

- **Email addresses** - flagged unless the domain is a known placeholder (`example.com`, `*.example`, GitHub's own `users.noreply.github.com`, and a short list of common doc-placeholder domains).
- **Absolute home paths** - POSIX (`/home/<user>`, `/Users/<user>`) and Windows (`C:\Users\<user>` or `C:/Users/<user>`), unless `<user>` is an obvious placeholder (`alice`, `example`, the GitHub-hosted runner's own account, and similar).
- **Credential and token prefixes** - Anthropic, OpenAI-shaped, AWS, GitHub, Slack, Google, and Stripe keys, plus a PEM private-key block. Each pattern matches a documented, high-entropy shape the issuer publishes, not a guess.
- **Private and link-local IPs, and `.local` hostnames** - the RFC 1918 ranges, RFC 3927 link-local, and mDNS-style `name.local` hosts, any of which can fingerprint a specific home or office network.
- **Secret-shaped filenames** - `.env` and its variants, SSH private keys, `.pem`/`.key`/`.pfx`/`.p12` files, `credentials.json`-style files, `.netrc`, `.npmrc`, `.pgpass`, and `secrets.{yaml,json,toml}`. Checked once per file added, not per line, since the finding is "this file shouldn't be here" rather than anything about a specific line in it.

Every pattern lives in `redaction_check.py`, next to a comment explaining why it's there. High-confidence shapes only. A gate that false-positives on ordinary prose gets disabled by the second annoyed contributor, which is worse than no gate at all.

## Quickstart

```yaml
name: Redaction check
on:
  pull_request:

permissions:
  contents: read

jobs:
  redaction:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0   # added-lines mode needs the base branch's history

      - uses: jimy-r/redaction-check-action@v1
```

`fetch-depth: 0` is required. The default shallow checkout doesn't include the base branch, so added-lines mode has nothing to diff against without it. The action sets up its own Python, so there's nothing else for the caller to install.

`@v1` is a moving major tag, repointed at the newest `v1.x.y` on every release; it is not re-tagged for patch or minor bumps you'd need to review individually. Pin to a specific tag (`@v1.2.3`) or commit SHA instead if you want releases to land on your own schedule.

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `patterns-file` | *(none)* | Path to an extra denylist, one regular expression per line. `#` comments and blank lines are skipped. |
| `fail-on` | `match` | `match` fails the step on any finding. `none` always exits 0 and reports findings as warnings instead, useful while first rolling the gate out on an existing repo. |
| `scan-mode` | `added-lines` | `added-lines` scans only what the PR adds. `all-files` walks every git-tracked file instead, for a full-repo audit run. |
| `base-ref` | *(auto)* | Branch to diff against. Defaults to the pull request's base branch. Set it explicitly when triggering on an event other than `pull_request`. |

## The masking guarantee

A finding never prints the thing it caught. Every match collapses to a short SHA-256 prefix (`sha256:9f2a1b3c4d5e`) before it reaches the log, so a run on a public repo can't itself become the leak. The test suite confirms this directly. The raw matched text is asserted absent from every code path that produces output, across every pattern class, checked in code rather than trusted by eye.

## Suppressing a false positive

Add `redaction-ok` anywhere on the line and the scanner skips it:

```python
# support contact: placeholder@example-corp.test  redaction-ok
```

Reach for this when a line is a genuine placeholder that happens to match a pattern's shape, not when it's a real finding you'd rather not deal with. The marker is plain text, so `grep -rn redaction-ok` is enough for a reviewer to audit how often it's used and whether that use still holds up.

## Honest limits

Shape-based scanning has real edges. A `.pem` file gets flagged whether it holds a private key or a public certificate, since a filename alone can't tell the difference. The built-in patterns are deliberately narrow. They cover the classes that show up most in a fast-moving or agent-assisted repo, not every credential format that exists, so an org with its own token formats should add them through `patterns-file` rather than expect this action to guess them. IPv6 addresses aren't covered in v0.1.

A clean run is a floor, not a ceiling. It means nothing here matched a known shape, which is a different claim from "a human read this diff and agreed." Pattern matching complements review; it was never going to replace it.

## Origin

This generalises the redaction gate built for [`agent-workspace-architecture`](https://github.com/jimy-r/agent-workspace-architecture?utm_source=github&utm_medium=repo&utm_campaign=redaction-check-action), where it runs as a required check on every pull request, including from forks, to catch what an AI agent might otherwise publish by mistake before a human reviews it. It's one of six repos published from that same workspace; the [interactive tour](https://jimy-r.github.io/agent-workspace-architecture/?utm_source=github&utm_medium=repo&utm_campaign=redaction-check-action) walks the rest.
