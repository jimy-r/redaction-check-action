# redaction-check-action

A composite GitHub Action that scans a pull request's added lines for the shapes of private content before they merge. It looks for email addresses, absolute home paths, credential and token prefixes, private-IP and hostname shapes, and filenames that are almost always meant to stay untracked.

It works entirely off the diff, against the *shape* a leak tends to take rather than a live denylist of real secrets (this is a public action, so it can't ship one). That keeps it fast and dependency-free, and it keeps the gate honest about its own scope. Catching common-shaped mistakes is not the same as guaranteeing privacy.

## What it catches

- **Email addresses** - flagged unless the domain is a known placeholder (`example.com`, `*.example`, GitHub's own `users.noreply.github.com`, and a short list of common doc-placeholder domains).
- **Absolute home paths** - POSIX (`/home/<user>`, `/Users/<user>`) and Windows (`C:\Users\<user>` or `C:/Users/<user>`), unless `<user>` is an obvious placeholder (`alice`, `example`, the GitHub-hosted runner's own account, and similar).
- **Credential and token prefixes** - Anthropic, OpenAI-shaped, AWS, GitHub, Slack, Google, and Stripe keys, plus a PEM private-key block. Each pattern matches a documented, high-entropy shape the issuer publishes, not a guess.
- **Private and link-local IPs, and `.local` hostnames** - the RFC 1918 ranges, RFC 3927 link-local, and mDNS-style `name.local` hosts, any of which can fingerprint a specific home or office network. A `.local.` segment before a config-file extension, as in `settings.local.json` or `docker-compose.local.yml`, is not read as a host. Any other file named after a host, such as `myhost.local.pem`, still is.
- **Secret-shaped filenames** - `.env` and its variants, SSH private keys, `.pem`/`.key`/`.pfx`/`.p12` files, `credentials.json`-style files, `.netrc`, `.npmrc`, `.pgpass`, and `secrets.{yaml,json,toml}`. Checked once per file added, not per line, since the finding is "this file shouldn't be here" rather than anything about a specific line in it. Binary and empty files count, as does an existing file renamed to one of these names.

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

`fetch-depth: 0` is required. The default shallow checkout doesn't include the base branch, so added-lines mode has nothing to diff against without it. On a `pull_request` event the scan diffs GitHub's test-merge commit against its own first parent, the base commit that merge was built on, so a base branch that moves while the check is queued can't break it. If the base branch was force-pushed and no longer contains that commit, the scan widens to cover whatever the pull request would bring back. If the diff can't be computed at all, or the checkout doesn't contain the pull request's head (the default checkout on `pull_request_target`), the step fails with an error rather than passing. The action sets up its own Python, so there's nothing else for the caller to install.

`@v1` is a moving major tag, repointed at the newest `v1.x.y` on every release; it is not re-tagged for patch or minor bumps you'd need to review individually. Pin to a specific tag (`@v1.2.3`) or commit SHA instead if you want releases to land on your own schedule.

### Earlier commits count too

A line added in one commit and deleted in a later one never shows in the pull request's net diff. The commit that added it is still on the branch, though, and once pushed that commit is public. A merge commit or a rebase merge also carries it onto the base branch. So the scan reads each commit in the range on its own as well as the net diff, and a finding that only an earlier commit holds names that commit's SHA.

A later commit that deletes the line doesn't clear that finding. Rewriting the branch without it does, with an interactive rebase and a force-push, because until then the commit stays public. GitHub can still serve the old commit by its SHA after that, so a real credential that reached a pushed commit should be treated as exposed and rotated. If the checkout is shallow and hides some of the pull request's commits, the action fetches their history from origin, and it fails rather than scan fewer.

### Running on push

A push has no pull request base, so `base-ref` has to be set. On a push to `main`, don't set it to `main`. The checkout is then `main`'s own new tip, so the range from `main` to it is empty and the step passes without scanning a line. Pass the commit the push started from instead, which GitHub puts in `github.event.before`:

```yaml
on:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  redaction:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0

      - uses: jimy-r/redaction-check-action@v1
        with:
          base-ref: ${{ github.event.before }}
```

`base-ref` takes a full commit SHA as well as a branch name. The push that creates a branch has no earlier commit (`github.event.before` is all zeros), so that one run fails with an error rather than passing.

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `patterns-file` | *(none)* | Path to an extra denylist, one regular expression per line. `#` comments and blank lines are skipped. |
| `fail-on` | `match` | `match` fails the step on any finding. `none` reports findings as warnings without failing on them, useful while first rolling the gate out on an existing repo. A diff that can't be computed fails the step either way. |
| `scan-mode` | `added-lines` | `added-lines` scans only what the PR adds. `all-files` walks every git-tracked file instead, for a full-repo audit run. |
| `base-ref` | *(auto)* | Branch to diff against, or a full commit SHA. Defaults to the pull request's base branch. A value that starts with `-` or holds a control character fails the step before any git command runs, since git would read it as an option. Set it explicitly when triggering on an event other than `pull_request`, and on `push` see [Running on push](#running-on-push). |
| `skip-scanner-files` | `false` | `true` skips `redaction_check.py` and `test_redaction_check.py` at the repository root. This action's own repository sets it, because its tests are full of secret-shaped fixtures on purpose. Leave it off anywhere else. With it off, files that happen to share those names are scanned like any other. |

## The masking guarantee

A finding never prints the thing it caught. Every match collapses to a short keyed hash (`hmac:9f2a1b3c4d5e`, HMAC-SHA256) before it reaches the log, so a run on a public repo can't itself become the leak. The key is random, made fresh for each run and never printed. The same value gets the same tag within a run, so repeats line up, but nobody can recompute a tag from guesses, even for a value with few possibilities like a private IP, and tags from two runs can't be matched up. The test suite confirms this directly. The raw matched text is asserted absent from every code path that produces output, across every pattern class, checked in code rather than trusted by eye.

## Suppressing a false positive

Add `redaction-ok` anywhere on the line and the scanner skips it:

```python
# support contact: placeholder@example-corp.test  redaction-ok
```

Reach for this when a line is a genuine placeholder that happens to match a pattern's shape, not when it's a real finding you'd rather not deal with. The marker is plain text, so `grep -rn redaction-ok` is enough for a reviewer to audit how often it's used and whether that use still holds up.

## Honest limits

Shape-based scanning has real edges. A `.pem` file gets flagged whether it holds a private key or a public certificate, since a filename alone can't tell the difference. The built-in patterns are deliberately narrow. They cover the classes that show up most in a fast-moving or agent-assisted repo, not every credential format that exists, so an org with its own token formats should add them through `patterns-file` rather than expect this action to guess them. IPv6 addresses aren't covered in v0.1. Images, fonts, compressed archives and audio or video files are checked by name only, as long as the file starts with its format's signature bytes. Real ones are full of byte runs shaped like emails and paths, so scanning their bytes would fail ordinary pull requests. A text file that only has one of those names is scanned, and so is an uncompressed `.tar`, which holds its files as they are.

A clean run is a floor, not a ceiling. It means nothing here matched a known shape, which is a different claim from "a human read this diff and agreed." Pattern matching complements review; it was never going to replace it.

## Origin

This generalises the redaction gate built for [`agent-workspace-architecture`](https://github.com/jimy-r/agent-workspace-architecture?utm_source=github&utm_medium=repo&utm_campaign=redaction-check-action), where it runs as a required check on every pull request, including from forks, to catch what an AI agent might otherwise publish by mistake before a human reviews it. It's one of six repos published from that same workspace; the [interactive tour](https://jimy-r.github.io/agent-workspace-architecture/?utm_source=github&utm_medium=repo&utm_campaign=redaction-check-action) walks the rest.

## Contributing

Pattern proposals and fixes are welcome. [`CONTRIBUTING.md`](CONTRIBUTING.md) has the setup, the test gate, and the one rule that is not negotiable.
