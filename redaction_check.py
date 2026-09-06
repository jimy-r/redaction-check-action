#!/usr/bin/env python3
"""Pattern-based redaction gate for pull requests.

Scans the ADDED lines of a pull request (or, in --mode all-files, every
git-tracked file) for the *shapes* of private content: email addresses,
absolute home paths, credential/token prefixes, private-IP/hostname shapes,
and common secret-file names. High-confidence patterns only -- a noisy gate
that false-positives on ordinary prose gets disabled, which is worse than no
gate at all.

Every finding is reported with the matched text MASKED (a short hash, never
the raw substring), so the gate's own output -- which lands in a CI log that
may be public -- cannot itself leak the thing it caught.

Exit 0 = clean (or findings under --fail-on none). Exit 1 = findings and
--fail-on match (the default). A genuine false positive: mark the specific
line with a `redaction-ok` comment, or override on merge.

Usage:
    python redaction_check.py --diff-file changes.diff
    git diff --unified=0 origin/main...HEAD | python redaction_check.py
    python redaction_check.py --mode all-files --root .
    python redaction_check.py --selftest
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

# Inline marker that suppresses a scan on the line it appears on. Documented
# in README.md as the false-positive escape hatch -- use it for a deliberate
# placeholder or a test fixture, not to wave through a real finding.
SUPPRESS_MARKER = "redaction-ok"

# This scanner's own source and test suite carry realistic-shaped fixtures on
# purpose (the positive test cases need real credential/path shapes to prove
# the patterns work). Exclude both from being scanned so the gate never
# self-flags when someone edits this action's own repo.
SELF_PATHS = {"redaction_check.py", "test_redaction_check.py"}

MAX_FILE_BYTES = 2_000_000  # skip pathologically large tracked files (--mode all-files)


# ---------------------------------------------------------------------------
# Pattern classes. Each one is a *shape*, not a lookup against real secrets --
# this file is public, so it must never hardcode anything it is meant to
# catch.
# ---------------------------------------------------------------------------

# Email addresses. Flagged because a personal or work address in a public
# diff identifies a real person. Placeholder/example domains are common in
# docs and are allowed through explicitly rather than guessed at.
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
EMAIL_ALLOW = re.compile(
    r"@("
    r"example\.(com|org|net)"  # RFC 2606 reserved domains
    r"|[^@\s]*\.(example|test|invalid|localhost)"  # RFC 2606 reserved TLDs
    r"|users\.noreply\.github\.com"  # GitHub's own address-hiding format
    r"|test\.com|domain\.com|company\.com|email\.com|acme\.com"
    r"|yourdomain\.com|yourcompany\.com"
    r")$",
    re.IGNORECASE,
)

# Absolute home paths -- POSIX (/home/<user>, macOS /Users/<user>) and
# Windows (C:\Users\<user> or C:/Users/<user>). A real username in one of
# these usually identifies a specific machine or person; a placeholder does
# not, so a short allowlist covers the common docs/example names plus the
# GitHub-hosted runner's own account.
HOME_PATH_RE = re.compile(
    r"(?:/home/|/Users/|[A-Za-z]:[\\/]Users[\\/])([A-Za-z0-9._-]+)"
)
PATH_PLACEHOLDERS = {
    "alice",
    "bob",
    "you",
    "user",
    "username",
    "home",
    "me",
    "example",
    "name",
    "youruser",
    "your-user",
    "jane",
    "johndoe",
    "john",
    "workspace",
    "runner",  # GitHub-hosted Linux/Windows runners use this account name
    "runneradmin",  # GitHub-hosted Windows runner's admin account
    "testuser",
    "ci",
}

# Credential / token prefixes. Each one is a documented, high-entropy shape
# published by the issuing service, not a guess -- so the false-positive
# rate on ordinary prose is low. New classes should meet the same bar.
CRED_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_-]{8,}")),
    # Checked after the Anthropic pattern's own hyphens break its longer
    # run, so a real sk-ant-... key is never double-counted under this one.
    ("OpenAI-style API key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "GitHub token",
        re.compile(r"\b(?:ghp_|gho_|ghu_|ghs_|github_pat_)[A-Za-z0-9_]{20,}\b"),
    ),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Stripe API key", re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]

# Private / link-local IPv4 shapes (RFC 1918 + RFC 3927). Next to other
# context these can fingerprint a specific home or office network. Loopback
# (127.0.0.0/8) is deliberately excluded -- it never identifies a network.
PRIVATE_IPV4_RE = re.compile(
    r"\b(?:"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3}"
    r")\b"
)
# The cloud metadata endpoint is a fixed public constant (AWS/GCP/Azure all
# use it), not information about anyone's network -- allow it through.
IP_ALLOW = {"169.254.169.254"}

# mDNS-style local hostnames (e.g. jamespc.local) often carry a real device
# or user name. Same placeholder logic as the home-path check, plus a few
# generic words common in networking docs.
LOCAL_HOSTNAME_RE = re.compile(
    r"\b([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)\.local\b"
)
HOSTNAME_PLACEHOLDERS = PATH_PLACEHOLDERS | {
    "test",
    "host",
    "service",
    "app",
    "myhost",
    "server",
    "localhost",
}

# Filenames that are almost always meant to stay untracked. Checked once per
# file (not per line) since flagging every line of a checked-in .env would
# just be noise on top of the one real finding: the file should not be here.
SECRET_FILENAME_EXEMPT = re.compile(r"\.(example|sample|template|dist)$", re.IGNORECASE)
SECRET_FILENAME_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("dotenv file", re.compile(r"^\.env(\.[A-Za-z0-9._-]+)?$", re.IGNORECASE)),
    (
        "SSH private key file",
        re.compile(r"^id_(rsa|dsa|ecdsa|ed25519)$", re.IGNORECASE),
    ),
    ("key/cert file", re.compile(r"\.(pem|key|pfx|p12)$", re.IGNORECASE)),
    (
        "credentials file",
        re.compile(
            r"(^|[_.-])(credentials|client[_-]secret|service[_-]?account)([_.-]|$)",
            re.IGNORECASE,
        ),
    ),
    ("netrc file", re.compile(r"^\.netrc$", re.IGNORECASE)),
    ("pgpass file", re.compile(r"^\.pgpass$", re.IGNORECASE)),
    ("npmrc file", re.compile(r"^\.npmrc$", re.IGNORECASE)),
    ("secrets file", re.compile(r"^secrets\.(ya?ml|json|toml)$", re.IGNORECASE)),
]


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    label: str
    masked: str


def mask(secret: str) -> str:
    """Collapse a matched secret to a short hash. Never return the raw text.

    The hash lets two findings of the same secret be recognised as the same
    without ever printing anything recoverable -- the point is that this
    scanner's own output can land in a CI log that may be public.
    """
    digest = hashlib.sha256(secret.encode("utf-8", "replace")).hexdigest()
    return f"sha256:{digest[:12]}"


def check_filename(path: str) -> str | None:
    """Return a label if path's basename looks like a secret file, else None."""
    basename = path.rsplit("/", 1)[-1]
    if SECRET_FILENAME_EXEMPT.search(basename):
        return None
    for label, rgx in SECRET_FILENAME_PATTERNS:
        if rgx.search(basename):
            return label
    return None


def scan_line(
    text: str, extra_patterns: Iterable[tuple[str, re.Pattern[str]]] = ()
) -> list[tuple[str, str]]:
    """Return (label, matched_text) pairs for one line of text."""
    if SUPPRESS_MARKER in text:
        return []
    hits: list[tuple[str, str]] = []
    for m in EMAIL_RE.finditer(text):
        if not EMAIL_ALLOW.search(m.group(0)):
            hits.append(("email address", m.group(0)))
    for m in HOME_PATH_RE.finditer(text):
        if m.group(1).lower() not in PATH_PLACEHOLDERS:
            hits.append(("absolute home path", m.group(0)))
    for label, rgx in CRED_PATTERNS:
        for m in rgx.finditer(text):
            hits.append((label, m.group(0)))
    for m in PRIVATE_IPV4_RE.finditer(text):
        if m.group(0) not in IP_ALLOW:
            hits.append(("private/link-local IP", m.group(0)))
    for m in LOCAL_HOSTNAME_RE.finditer(text):
        if m.group(1).lower() not in HOSTNAME_PLACEHOLDERS:
            hits.append(("mDNS/.local hostname", m.group(0)))
    for label, rgx in extra_patterns:
        for m in rgx.finditer(text):
            hits.append((label, m.group(0)))
    return hits


def load_extra_patterns(path: str) -> list[tuple[str, re.Pattern[str]]]:
    """Load an extra denylist: one regex per line, '#' comments, blanks skipped."""
    patterns: list[tuple[str, re.Pattern[str]]] = []
    with open(path, encoding="utf-8") as f:
        for i, raw in enumerate(f, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rgx = re.compile(line)
            except re.error as exc:
                raise SystemExit(
                    f"{path}:{i}: invalid regex in patterns file: {exc}"
                ) from exc
            patterns.append((f"custom pattern ({line[:40]})", rgx))
    return patterns


# ---------------------------------------------------------------------------
# Diff parsing
# ---------------------------------------------------------------------------

DIFF_HEADER_RE = re.compile(r"^diff --git ")
HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def parse_added_lines(diff_text: str) -> Iterator[tuple[str, int, str]]:
    """Yield (path, lineno, text) for every added line in a unified diff.

    Handles multiple files and multiple hunks per file, renames (with or
    without content changes), deleted and binary files (which contribute no
    hunks, so nothing is yielded for them), and a trailing "no newline at
    end of file" marker. Context lines (present in a diff generated with
    more than zero lines of context) advance the line counter without being
    yielded, so this also works on a normal, non `--unified=0` diff.
    """
    path: str | None = None
    lineno = 0
    for line in diff_text.splitlines():
        if DIFF_HEADER_RE.match(line):
            path = None  # each file block starts clean; no cross-file bleed
            continue
        if line.startswith("+++ "):
            new_path = line[4:]
            if new_path == "/dev/null":
                path = None
            elif new_path.startswith("b/"):
                path = new_path[2:]
            else:
                path = new_path
            continue
        if line.startswith("@@"):
            m = HUNK_RE.match(line)
            lineno = int(m.group(1)) if m else 0
            continue
        if line.startswith("\\"):
            continue  # "\ No newline at end of file"
        if path is None:
            continue
        if line.startswith("+"):
            yield path, lineno, line[1:]
            lineno += 1
        elif line.startswith("-"):
            continue  # old-side-only line; new-file line counter untouched
        elif line.startswith(" "):
            lineno += 1  # context line present; advances but is not added


# `text=True` alone decodes with the process's preferred encoding, which on a
# Windows runner is the console codepage (cp1252). A diff carrying any byte
# outside that codepage — a smart quote pasted into a doc, a UTF-8 filename, a
# binary hunk header — then dies with UnicodeDecodeError before a single pattern
# is scanned, so the gate fails closed on content it never looked at. Git emits
# UTF-8; decode it as UTF-8 and replace anything undecodable, because a mangled
# character in a diff line is still scannable and a crash is not.
def get_diff_via_git(base: str, root: str = ".") -> str:
    return subprocess.run(
        ["git", "-C", root, "diff", "--unified=0", f"{base}...HEAD"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    ).stdout


def iter_tracked_files(root: str = ".") -> Iterator[str]:
    result = subprocess.run(
        ["git", "-C", root, "ls-files"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    for line in result.stdout.splitlines():
        if line:
            yield line


# ---------------------------------------------------------------------------
# Scan drivers
# ---------------------------------------------------------------------------


def scan_added_lines(
    diff_text: str, extra_patterns: Iterable[tuple[str, re.Pattern[str]]] = ()
) -> list[Finding]:
    findings: list[Finding] = []
    seen_paths: set[str] = set()
    for path, lineno, text in parse_added_lines(diff_text):
        if path in SELF_PATHS:
            continue
        if path not in seen_paths:
            seen_paths.add(path)
            label = check_filename(path)
            if label:
                findings.append(Finding(path, lineno, label, mask(path)))
        for hit_label, matched in scan_line(text, extra_patterns):
            findings.append(Finding(path, lineno, hit_label, mask(matched)))
    return findings


def scan_all_files(
    root: str = ".", extra_patterns: Iterable[tuple[str, re.Pattern[str]]] = ()
) -> list[Finding]:
    findings: list[Finding] = []
    root_path = Path(root)
    for rel_path in iter_tracked_files(root):
        if rel_path in SELF_PATHS:
            continue
        label = check_filename(rel_path)
        if label:
            findings.append(Finding(rel_path, 1, label, mask(rel_path)))
        full_path = root_path / rel_path
        try:
            if full_path.stat().st_size > MAX_FILE_BYTES:
                continue
            with open(full_path, encoding="utf-8") as f:
                for lineno, text in enumerate(f, start=1):
                    for hit_label, matched in scan_line(text, extra_patterns):
                        findings.append(
                            Finding(rel_path, lineno, hit_label, mask(matched))
                        )
        except (UnicodeDecodeError, OSError):
            continue  # binary or unreadable; the filename check above still ran
    return findings


# ---------------------------------------------------------------------------
# Selftest -- built-in pattern assertions, no git required
# ---------------------------------------------------------------------------


def run_selftest() -> int:
    # Sensitive shapes are built by concatenation so this file carries no
    # contiguous secret-shaped string for an unrelated static scanner (e.g.
    # GitHub's own secret-scanning / push protection) to trip on. The
    # runtime values still exercise every pattern in scan_line().
    must_flag = [
        "contact me at real.person" + "@gmail.com today",
        "path was /home/" + "realname" + "/.config",
        "C:" + "\\Users\\" + "realname\\notes",
        "token " + "sk-ant-" + "EXAMPLE00000000000",
        "key " + "AKIA" + "EXAMPLE000000000" + " here",
        "internal host at 192.168" + ".1.42",
        "reachable at build7" + ".local on the LAN",
    ]
    must_pass = [
        "see /home/alice/project for the example",
        "use " + "C:/" + "Users/alice/workspace",
        "email the author at user@example.com",
        "vector embeddings and data sovereignty are fine",
        "reference ~/.claude/settings.json (generic)",
        "loopback is 127.0.0.1 in every stack",
        "runs fine on runner" + ".local for CI",
    ]
    ok = True
    for s in must_flag:
        if not scan_line(s):
            print(f"SELFTEST FAIL (should flag): {s}", file=sys.stderr)
            ok = False
    for s in must_pass:
        hits = scan_line(s)
        if hits:
            print(f"SELFTEST FAIL (should pass): {s} -> {hits}", file=sys.stderr)
            ok = False
    print("selftest: PASS" if ok else "selftest: FAIL")
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def report(findings: list[Finding], fail_on: str) -> int:
    level = "error" if fail_on == "match" else "warning"
    for f in findings:
        print(
            f"::{level} file={f.path},line={f.line}::"
            f"Possible {f.label}: {f.masked} (masked, not the real value). "
            f"Generalise or remove before this can merge, or mark the line "
            f"with `{SUPPRESS_MARKER}` if it is a deliberate placeholder."
        )
    if findings:
        print(
            f"\nRedaction gate: {len(findings)} potential leak(s). "
            f"Use placeholders instead of real values, or add `{SUPPRESS_MARKER}` "
            f"on the line if it is a deliberate fixture or example.",
            file=sys.stderr,
        )
    else:
        print("Redaction gate: clean.")
    return 1 if (findings and fail_on == "match") else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--mode",
        choices=["added-lines", "all-files"],
        default="added-lines",
        help="added-lines (default) scans a diff; all-files walks every tracked file",
    )
    ap.add_argument(
        "--diff-file",
        help="unified diff to scan in added-lines mode; omit (or pass -) to read stdin",
    )
    ap.add_argument(
        "--base",
        help="if set, added-lines mode runs `git diff --unified=0 <base>...HEAD` itself "
        "instead of reading --diff-file/stdin",
    )
    ap.add_argument("--root", default=".", help="repo root for all-files mode / --base")
    ap.add_argument("--patterns-file", help="extra denylist file: one regex per line")
    ap.add_argument(
        "--fail-on",
        choices=["match", "none"],
        default="match",
        help="match (default) exits 1 on any finding; none always exits 0 (report only)",
    )
    ap.add_argument(
        "--selftest",
        action="store_true",
        help="run built-in pattern assertions and exit",
    )
    args = ap.parse_args(argv)

    if args.selftest:
        return run_selftest()

    extra_patterns = (
        load_extra_patterns(args.patterns_file) if args.patterns_file else []
    )

    if args.mode == "all-files":
        findings = scan_all_files(args.root, extra_patterns)
    else:
        if args.base:
            diff_text = get_diff_via_git(args.base, args.root)
        elif args.diff_file and args.diff_file != "-":
            with open(args.diff_file, encoding="utf-8", errors="replace") as f:
                diff_text = f.read()
        else:
            diff_text = sys.stdin.read()
        findings = scan_added_lines(diff_text, extra_patterns)

    return report(findings, args.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
