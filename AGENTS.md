# AGENTS.md

Instructions for any coding agent working in this repository, in the
[agents.md](https://agents.md/) format.

This repo is a composite GitHub Action that scans a pull request's added lines
for the shapes of private content. The scanner is one stdlib-only file,
`redaction_check.py`, and the action wraps it in `action.yml`.

Run the tests before you commit: `python -m unittest test_redaction_check -v`,
then `ruff check .` and `ruff format --check .`.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full contributor rules,
including the masking guarantee, which is not negotiable.
