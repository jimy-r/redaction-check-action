# AGENTS.md

Instructions for any coding agent working in this repository, in the
[agents.md](https://agents.md/) format.

This repo is a composite GitHub Action that scans a pull request's added lines
for the shapes of private content. The scanner is one stdlib-only file,
`redaction_check.py`, and the action wraps it in `action.yml`.

Run the tests before you commit: `python -m unittest test_redaction_check -v`,
then `ruff check .` and `ruff format --check .`.

This repo is public, so a commit must carry no personal identifiers, no real
credentials, no absolute paths from your own machine and no content copied
from a private workspace. A test fixture that needs a private shape builds it
from split strings at runtime, as the existing tests do.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full contributor rules,
including the masking guarantee, which is not negotiable.
