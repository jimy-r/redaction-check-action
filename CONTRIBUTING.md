# Contributing

Issues and pull requests are welcome, pattern proposals especially. This is maintained best-effort by one person, so a reply may take a week.

## The rule that is not negotiable

A finding never prints the thing it caught. Every match collapses to a short SHA-256 prefix before it reaches the log, so a run on a public repository cannot itself become the leak. `test_redaction_check.py` asserts the raw matched text is absent from every output path, for every pattern class. A change that prints a matched value, adds a verbose mode that prints one, or drops one of those assertions gets closed on principle however good the rest of it is.

The second rule follows from the first. Patterns stay high-confidence. A gate that false-positives on ordinary prose gets disabled by the second annoyed contributor, which is worse than no gate at all.

## Setting up

Python 3.10 or newer and git. Nothing else. The scanner is a single stdlib-only file, and the action installs its own Python for callers.

```bash
git clone https://github.com/jimy-r/redaction-check-action.git
cd redaction-check-action
python -m unittest test_redaction_check -v
```

Run the scanner directly to see what it does on a real tree:

```bash
python redaction_check.py --mode all-files          # walk every tracked file
python redaction_check.py --base main               # added lines against a base ref
python redaction_check.py --selftest                # built-in pattern assertions
```

## Before you push

```bash
python -m unittest test_redaction_check -v
pip install -r .github/requirements-ci.txt
ruff check .
ruff format --check .
```

CI runs those on Python 3.10 and 3.13, then a `self-test` job that dogfoods the action against a fixture diff: it injects a detectable shape and asserts the action fails, then replaces it with clean content and asserts the action passes. A pattern change that breaks either half fails there instead of in a consumer's repository.

Lint pins live in `.github/requirements-ci.txt` and the explicit select lives in `ruff.toml`, so a ruff bump cannot silently change what is linted. Install the pinned version if a finding looks unfamiliar.

## Adding or changing a pattern

- Every pattern lives in `redaction_check.py` beside a comment saying why it is there and which published shape it matches.
- Documented, high-entropy, issuer-published shapes only. A guessed shape is a false-positive generator.
- Add both cases to `test_redaction_check.py`: a positive that matches, and the nearest ordinary-prose lookalike that must not.
- Add the masking assertion for the new class.
- Update the "What it catches" list in [`README.md`](README.md) in the same change.
- Organisation-specific token formats belong in a caller's `patterns-file`, not in the built-in set.

## Scope

This repository is the action and its scanner. The gate it generalises lives in [agent-workspace-architecture](https://github.com/jimy-r/agent-workspace-architecture), which takes pattern-library proposals of its own. Bugs in GitHub Actions itself go to GitHub.

## Commits and pull requests

[Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `chore:`), one logical change per commit. Agent-assisted commits carry a `Co-Authored-By:` trailer.

A pull request description says what changed and why, and reports the test run. `@v1` is a moving major tag that every consumer resolves to, so a scanner change reaches them on the next release. If the change alters what the gate flags, say so in the first line and a reviewer will look there first.

## Security

Do not report a vulnerability in an issue or a pull request. [`SECURITY.md`](SECURITY.md) has the private path.
