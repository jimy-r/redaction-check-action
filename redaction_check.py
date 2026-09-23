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
--fail-on match (the default). Exit 2 = --base was given and the diff to
scan could not be computed, which is never a pass, whatever --fail-on says.
A genuine false positive: mark the specific line with a `redaction-ok`
comment, or override on merge.

Usage:
    python redaction_check.py --diff-file changes.diff
    git diff --unified=0 origin/main...HEAD | python redaction_check.py
    python redaction_check.py --base origin/main
    python redaction_check.py --base origin/main --pr-head <sha>  # PR merge ref
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

# mDNS-style local hostnames (e.g. devbox.local) often carry a real device
# or user name. Same placeholder logic as the home-path check, plus a few
# generic words common in networking docs. The lookahead exempts a `.local.`
# segment only before a config-file extension, the per-machine config
# convention (settings.local.json, docker-compose.local.yml). A host named
# inside any other file name (devbox.local.pem, devbox.local.conf, a log
# named user@devbox.local.log) and a sentence-final `host.local.` still match.
LOCAL_HOSTNAME_RE = re.compile(
    r"\b([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)\.local\b"
    r"(?!\.(?:json|ya?ml|toml|ini|env|js|ts|xml|properties)\b)"
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

# Git's C-style escapes inside a quoted path. An octal escape is one byte.
C_ESCAPE_RE = re.compile(r"\\(?:([0-7]{3})|(.))", re.DOTALL)
C_ESCAPES = {
    "a": "\a",
    "b": "\b",
    "t": "\t",
    "n": "\n",
    "v": "\v",
    "f": "\f",
    "r": "\r",
}


def unquote_header_path(raw: str) -> str:
    """Return a path from a diff header as it is on disk.

    Git appends a tab to a header path that contains a space. It C-quotes a
    path holding a control character, a double quote or a backslash (and,
    unless core.quotePath is false, any non-ASCII byte), writing each odd
    byte as an escape. Left as printed, `"b/caf\\303\\251/.env"` or
    `b/my dir/.env<TAB>` has no basename that matches `.env`.
    """
    if raw.endswith("\t"):
        raw = raw[:-1]
    if len(raw) < 2 or raw[0] != '"' or raw[-1] != '"':
        return raw
    body = raw[1:-1]
    out = bytearray()
    pos = 0
    for m in C_ESCAPE_RE.finditer(body):
        out += body[pos : m.start()].encode("utf-8")
        octal, char = m.groups()
        if octal:
            out.append(int(octal, 8) & 0xFF)
        else:
            out += C_ESCAPES.get(char, char).encode("utf-8")
        pos = m.end()
    out += body[pos:].encode("utf-8")
    return out.decode("utf-8", "replace")


def parse_added_lines(diff_text: str) -> Iterator[tuple[str, int, str]]:
    """Yield (path, lineno, text) for every added line in a unified diff.

    Handles multiple files and multiple hunks per file, renames (with or
    without content changes), deleted and binary files (which contribute no
    hunks, so nothing is yielded for them), and a trailing "no newline at
    end of file" marker. Context lines (present in a diff generated with
    more than zero lines of context) advance the line counter without being
    yielded, so this also works on a normal, non `--unified=0` diff.

    Lines split on "\\n" only. A CR, a form feed or a U+2028 inside an added
    line is part of its content, never a break that would strip the "+" from
    the text after it and hide that text from the scan.

    `---` and `+++` are file headers only between a `diff --git` line and
    that file's first hunk. Inside a hunk, `+++ /dev/null` is an added line
    whose text starts with "++ ", not a header that ends the file.
    """
    path: str | None = None
    lineno = 0
    in_header = True  # a plain unified diff opens with ---/+++, no diff --git
    for line in diff_text.split("\n"):
        if DIFF_HEADER_RE.match(line):
            path = None  # each file block starts clean; no cross-file bleed
            in_header = True
            continue
        if line.startswith("@@"):
            m = HUNK_RE.match(line)
            lineno = int(m.group(1)) if m else 0
            in_header = False
            continue
        if in_header:
            if line.startswith("+++ "):
                # rstrip: a diff file saved with CRLF line endings.
                new_path = unquote_header_path(line[4:].rstrip("\r"))
                if new_path == "/dev/null":
                    path = None
                elif new_path.startswith("b/"):
                    path = new_path[2:]
                else:
                    path = new_path
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


# Git's output is captured as bytes and decoded by _text, never by subprocess.
# `text=True` decodes with the process's preferred encoding, which on a Windows
# runner is the console codepage (cp1252), so a diff carrying any byte outside
# it (a smart quote pasted into a doc, a UTF-8 filename) died with
# UnicodeDecodeError before a single pattern ran. It also turns on universal
# newlines, which rewrite a lone CR as a line break, so the second line of a
# CR-only file lost its "+" and was never scanned. Git emits UTF-8. Decode it
# as UTF-8 and replace anything undecodable, because a mangled character in a
# diff line is still scannable and a crash is not.
def _git(root: str, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["git", "-C", root, *args], capture_output=True, check=False)


def _text(data: bytes) -> str:
    return data.decode("utf-8", "replace")


def _last_error_line(result: subprocess.CompletedProcess[bytes]) -> str:
    lines = _text(result.stderr).strip().splitlines()
    return lines[-1] if lines else f"git exited with status {result.returncode}"


class DiffError(Exception):
    """The diff to scan could not be computed. Never a pass, whatever --fail-on says."""


def commit_parents(rev: str, root: str = ".") -> list[str]:
    """Return the parent SHAs recorded in a commit object, first parent first.

    Read from the object itself because a shallow clone hides a boundary
    commit's parents from `rev-parse <rev>^1` and from `%P`, while the object
    still names them.
    """
    result = _git(root, "cat-file", "commit", rev)
    if result.returncode != 0:
        raise DiffError(f"cannot read commit {rev}: {_last_error_line(result)}")
    parents = []
    for line in _text(result.stdout).split("\n"):
        if not line:
            break  # end of the header; a message line may start with "parent "
        if line.startswith("parent "):
            parents.append(line.removeprefix("parent "))
    return parents


def _has_commit(rev: str, root: str) -> bool:
    return _git(root, "cat-file", "-e", f"{rev}^{{commit}}").returncode == 0


def _history_is_complete(rev: str, root: str) -> bool:
    """True when no shallow boundary cuts off any ancestor of rev."""
    shallow = _git(root, "rev-parse", "--is-shallow-repository")
    if _text(shallow.stdout).strip() != "true":
        return True
    roots = _git(root, "rev-list", "--max-parents=0", rev)
    if roots.returncode != 0:
        return False
    # A shallow boundary is listed as a root, but its commit object still
    # names the parents the clone does not have.
    return not any(commit_parents(sha, root) for sha in _text(roots.stdout).split())


def _rewritten_base_range(
    base: str, first_parent: str, head_sha: str, root: str
) -> tuple[str, str, str] | None:
    """Widen a test-merge range whose base branch was force-pushed.

    The test merge's first parent was the base branch's tip when GitHub built
    it. A base that has only moved forward still contains that commit, and
    the first-parent range is exactly the pull request's change. A base that
    was rewritten does not, and whatever the rewrite dropped but the pull
    request still carries (a leak purged from the base, say) comes back when
    it merges. So the range widens to the merge base of base and HEAD, what
    `git diff base...HEAD` shows. Returns None to keep the first-parent range,
    including when base is missing, since that range never needs it.
    """
    resolved = _git(root, "rev-parse", "--verify", f"{base}^{{commit}}")
    if resolved.returncode != 0:
        return None
    base_sha = _text(resolved.stdout).strip()
    contains = _git(root, "merge-base", "--is-ancestor", first_parent, base_sha)
    if contains.returncode == 0:
        return None
    merge_base = _git(root, "merge-base", base_sha, head_sha)
    if merge_base.returncode == 0:
        how = (
            f"HEAD against its merge base with {base}, because {base} was "
            "rewritten and no longer contains the commit the test merge was built on"
        )
        return _text(merge_base.stdout).strip(), head_sha, how
    if _history_is_complete(base_sha, root):
        raise DiffError(
            f"{base} no longer contains {first_parent[:12]}, the commit this test "
            f"merge was built on, so {base} was rewritten. The scan has to widen "
            f"to the merge base of {base} and HEAD, and this clone has none. "
            "Check out with fetch-depth: 0."
        )
    # A shallow boundary hides part of the base's own history (a --depth
    # fetch of the base does this), so a rewrite cannot be told apart from a
    # base whose history is merely out of view. Keep the first-parent range.
    return None


def resolve_diff_range(
    base: str, root: str = ".", pr_head: str | None = None
) -> tuple[str, str, str]:
    """Return (from_commit, to_commit, how) spanning the lines HEAD adds.

    With pr_head set, and HEAD being GitHub's test-merge commit for it (first
    parent: the base commit the merge was built on, second parent: pr_head),
    the range is HEAD's first parent to HEAD. That is the pull request's own
    change, and it needs no merge base with the base branch's current tip, so
    a base that moves while the check is queued cannot break it. A shallow
    checkout that lacks the first parent is deepened by one commit from
    origin. A base that was force-pushed instead widens the range; see
    _rewritten_base_range.

    Otherwise the range starts at the merge base of base and HEAD, which is
    what `git diff base...HEAD` shows. Raises DiffError, with the reason, when
    the range cannot be computed.
    """
    head = _git(root, "rev-parse", "--verify", "HEAD^{commit}")
    if head.returncode != 0:
        raise DiffError(f"HEAD does not name a commit: {_last_error_line(head)}")
    head_sha = _text(head.stdout).strip()

    how = f"HEAD against its merge base with {base}"
    if pr_head:
        parents = commit_parents(head_sha, root)
        if len(parents) == 2 and parents[1] == pr_head.strip().lower():
            first_parent = parents[0]
            if not _has_commit(first_parent, root):
                fetch = _git(
                    root, "fetch", "--no-tags", "--deepen=1", "origin", head_sha
                )
                if not _has_commit(first_parent, root):
                    detail = (
                        _last_error_line(fetch)
                        if fetch.returncode
                        else "the fetch ran but did not bring it in"
                    )
                    raise DiffError(
                        f"HEAD is the test-merge commit for {pr_head[:12]}, but its "
                        f"first parent {first_parent[:12]} is not in this clone and "
                        f"deepening the fetch from origin failed ({detail})."
                    )
            widened = _rewritten_base_range(base, first_parent, head_sha, root)
            if widened:
                return widened
            how = "the pull request's test-merge commit against its first parent"
            return first_parent, head_sha, how
        # Anything else must at least contain the pull request's head, or the
        # merge-base range below scans some other change. pull_request_target
        # checks out the base branch by default, and that range is then empty.
        contains = _git(root, "merge-base", "--is-ancestor", pr_head.strip(), head_sha)
        if contains.returncode != 0:
            raise DiffError(
                f"HEAD does not contain pull request head {pr_head[:12]}, so this "
                "checkout is not the pull request's code. A pull_request_target "
                "run checks out the base branch unless told otherwise. Check out "
                "the pull request's head or merge commit."
            )
        how += f", since HEAD does not merge pull request head {pr_head[:12]}"

    base_commit = _git(root, "rev-parse", "--verify", f"{base}^{{commit}}")
    if base_commit.returncode != 0:
        raise DiffError(
            f"{base} does not name a commit in this clone. Check out with "
            "fetch-depth: 0 so the base branch's history is present."
        )
    base_sha = _text(base_commit.stdout).strip()
    merge_base = _git(root, "merge-base", base_sha, head_sha)
    if merge_base.returncode != 0:
        shallow = _git(root, "rev-parse", "--is-shallow-repository")
        hint = (
            " This clone is shallow, which hides the history they share. Check "
            "out with fetch-depth: 0, and never re-fetch the base with --depth."
            if _text(shallow.stdout).strip() == "true"
            else " Their histories share no commit."
        )
        raise DiffError(
            f"{base} and HEAD have no merge base, so the lines HEAD adds cannot "
            f"be worked out.{hint}"
        )
    return _text(merge_base.stdout).strip(), head_sha, how


def git_diff(from_commit: str, to_commit: str, root: str = ".") -> str:
    # --no-color: a runner's color.ui=always would otherwise put escape codes
    # in front of every line, and the parser would recognise none of them.
    # core.quotePath=false: a non-ASCII path prints as itself, not quoted.
    result = _git(
        root,
        "-c",
        "core.quotePath=false",
        "diff",
        "--no-color",
        "--unified=0",
        from_commit,
        to_commit,
    )
    if result.returncode != 0:
        raise DiffError(f"git diff failed: {_last_error_line(result)}")
    return _text(result.stdout)


def get_diff_via_git(base: str, root: str = ".", pr_head: str | None = None) -> str:
    """Return the --unified=0 diff of the lines HEAD adds; see resolve_diff_range."""
    from_commit, to_commit, _how = resolve_diff_range(base, root, pr_head)
    return git_diff(from_commit, to_commit, root)


def iter_tracked_files(root: str = ".") -> Iterator[str]:
    # -z prints each name NUL-terminated and never quoted. Without it a
    # non-ASCII name arrived as "caf\303\251/.env", which neither matched a
    # secret filename nor opened.
    result = subprocess.run(
        ["git", "-C", root, "ls-files", "-z"], capture_output=True, check=True
    )
    for name in _text(result.stdout).split("\0"):
        if name:
            yield name


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
        "the share lives on build7" + ".local.",
        "ssl_certificate /etc/ssl/build7" + ".local.pem;",
    ]
    must_pass = [
        "see /home/alice/project for the example",
        "use " + "C:/" + "Users/alice/workspace",
        "email the author at user@example.com",
        "vector embeddings and data sovereignty are fine",
        "reference ~/.claude/settings.json (generic)",
        "loopback is 127.0.0.1 in every stack",
        "runs fine on runner" + ".local for CI",
        "copy .claude/settings" + ".local.json over the defaults",
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
    ap.add_argument(
        "--pr-head",
        metavar="SHA",
        help="with --base: the pull request's head commit (full SHA). When HEAD is "
        "the test-merge commit that merges it, the diff is HEAD against its own "
        "first parent, which needs no merge base with a base branch that has moved",
    )
    ap.add_argument("--root", default=".", help="repo root for all-files mode / --base")
    ap.add_argument("--patterns-file", help="extra denylist file: one regex per line")
    ap.add_argument(
        "--fail-on",
        choices=["match", "none"],
        default="match",
        help="match (default) exits 1 on any finding; none reports findings "
        "without failing on them",
    )
    ap.add_argument(
        "--selftest",
        action="store_true",
        help="run built-in pattern assertions and exit",
    )
    args = ap.parse_args(argv)
    if args.pr_head and not args.base:
        ap.error("--pr-head needs --base, the fallback when HEAD is not a merge ref")

    if args.selftest:
        return run_selftest()

    extra_patterns = (
        load_extra_patterns(args.patterns_file) if args.patterns_file else []
    )

    if args.mode == "all-files":
        findings = scan_all_files(args.root, extra_patterns)
    else:
        if args.base:
            try:
                from_commit, to_commit, how = resolve_diff_range(
                    args.base, args.root, args.pr_head
                )
                diff_text = git_diff(from_commit, to_commit, args.root)
            except DiffError as exc:
                print(f"::error::Redaction gate cannot compute the diff to scan. {exc}")
                return 2
            print(
                f"Scanning lines added in {from_commit[:12]}..{to_commit[:12]} ({how})."
            )
            if not diff_text.strip():
                print(
                    "::notice::That range has no changes, so there was nothing to scan."
                )
        elif args.diff_file and args.diff_file != "-":
            # Bytes, as for git's own output: a text-mode read would turn a
            # lone CR into a line break before the parser saw the line.
            with open(args.diff_file, "rb") as f:
                diff_text = _text(f.read())
        else:
            stdin_bytes = getattr(sys.stdin, "buffer", None)
            diff_text = _text(stdin_bytes.read()) if stdin_bytes else sys.stdin.read()
        findings = scan_added_lines(diff_text, extra_patterns)

    return report(findings, args.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
