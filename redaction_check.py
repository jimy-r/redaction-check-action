#!/usr/bin/env python3
"""Pattern-based redaction gate for pull requests.

Scans the ADDED lines of a pull request (or, in --mode all-files, every
git-tracked file) for the *shapes* of private content: email addresses,
absolute home paths, credential/token prefixes, private-IP/hostname shapes,
and common secret-file names. With --base, both the range's net diff and
each of its commits on its own are scanned. High-confidence patterns only --
a noisy gate that false-positives on ordinary prose gets disabled, which is
worse than no gate at all.

Every finding is reported with the matched text MASKED (a keyed hash, never
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
import hmac
import re
import secrets
import subprocess
import sys
from collections.abc import Callable, Collection, Iterable, Iterator
from dataclasses import dataclass, replace
from pathlib import Path

# Inline marker that suppresses a scan on the line it appears on. Documented
# in README.md as the false-positive escape hatch -- use it for a deliberate
# placeholder or a test fixture, not to wave through a real finding.
SUPPRESS_MARKER = "redaction-ok"

# This scanner's own source and test suite carry realistic-shaped fixtures on
# purpose (the positive test cases need real credential/path shapes to prove
# the patterns work). --skip-scanner-files excludes both, for this action's own
# repository. It is off by default: skipping them unasked let a consumer's
# file that merely shared one of these names through unscanned.
SELF_PATHS = frozenset({"redaction_check.py", "test_redaction_check.py"})

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

# Binary media. The diff runs with --text, so a NUL byte or a `-diff`
# attribute cannot hide a text file's content, and that prints these files as
# lines too. Real ones are full of email- and path-shaped byte runs (read as
# text, 202 of a sample of 336 system fonts produced a finding), so their
# content is skipped, but only when the file starts the way its format does.
# The name alone skipped a text file called notes.png. Tar is not here: an
# uncompressed tar holds its member files byte for byte. Names are checked
# either way. Each signature is a bytes regex matched at the file's start.
_ISO_MEDIA = rb".{4}ftyp"  # MP4 and HEIF share the ISO base media file format
_RIFF = rb"RIFF.{4}"
MEDIA_SIGNATURES = {
    # images
    "png": rb"\x89PNG\r\n\x1a\n",
    "jpg": rb"\xff\xd8\xff",
    "jpeg": rb"\xff\xd8\xff",
    "gif": rb"GIF8[79]a",
    "bmp": rb"BM.{4}\x00{4}",
    "ico": rb"\x00\x00\x01\x00",
    "icns": rb"icns",
    "webp": _RIFF + rb"WEBP",
    "tif": rb"II\*\x00|MM\x00\*",
    "tiff": rb"II\*\x00|MM\x00\*",
    "avif": _ISO_MEDIA,
    "heic": _ISO_MEDIA,
    "heif": _ISO_MEDIA,
    # fonts
    "ttf": rb"\x00\x01\x00\x00|true",
    "otf": rb"OTTO|\x00\x01\x00\x00",
    "ttc": rb"ttcf",
    "woff": rb"wOFF",
    "woff2": rb"wOF2",
    "eot": rb".{34}LP",
    # compressed archives
    "zip": rb"PK\x03\x04|PK\x05\x06",
    "jar": rb"PK\x03\x04|PK\x05\x06",
    "whl": rb"PK\x03\x04|PK\x05\x06",
    "gz": rb"\x1f\x8b",
    "tgz": rb"\x1f\x8b",
    "bz2": rb"BZh",
    "xz": rb"\xfd7zXZ\x00",
    "zst": rb"\x28\xb5\x2f\xfd",
    "7z": rb"7z\xbc\xaf\x27\x1c",
    "rar": rb"Rar!\x1a\x07",
    # audio and video
    "mp3": rb"ID3|\xff[\xe2\xe3\xf2\xf3\xfa\xfb]",
    "m4a": _ISO_MEDIA,
    "mp4": _ISO_MEDIA,
    "m4v": _ISO_MEDIA,
    "mov": rb".{4}(?:ftyp|moov|mdat|wide|free)",
    "ogg": rb"OggS",
    "wav": _RIFF + rb"WAVE",
    "flac": rb"fLaC",
    "webm": rb"\x1a\x45\xdf\xa3",
    "mkv": rb"\x1a\x45\xdf\xa3",
    "avi": _RIFF + rb"AVI ",
}
MEDIA_RE = {
    ext: re.compile(rb"\A(?:" + signature + rb")", re.DOTALL)
    for ext, signature in MEDIA_SIGNATURES.items()
}
MEDIA_HEAD_BYTES = 64  # every signature above sits in a file's first 36 bytes


def media_extension(path: str) -> str:
    basename = path.rsplit("/", 1)[-1]
    return basename.rsplit(".", 1)[1].lower() if "." in basename else ""


def is_media(path: str, head: bytes) -> bool:
    """True when path has a media extension and head starts as that format does."""
    signature = MEDIA_RE.get(media_extension(path))
    return bool(signature and signature.match(head))


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    label: str
    masked: str
    commit: str = ""  # set when the line came from one commit's own patch


# The mask key, random and fresh for each run, and never printed. An unsalted
# hash of a value with few possibilities could be reversed from the log alone:
# hashing all of 10/8 recovered a masked private IP in about two seconds.
MASK_KEY = secrets.token_bytes(32)


def mask(secret: str) -> str:
    """Collapse a matched secret to a short keyed hash. Never return the raw text.

    Within one run the same secret always gives the same tag, so two findings
    of it can be recognised as the same and merge_findings can dedupe them.
    Without the key nobody can recompute a tag from guesses, and tags from
    different runs cannot be linked. The point is that this scanner's own
    output can land in a CI log that may be public.
    """
    tag = hmac.new(MASK_KEY, secret.encode("utf-8", "replace"), hashlib.sha256)
    return f"hmac:{tag.hexdigest()[:12]}"


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

# `diff --cc` and `diff --combined` open a merge commit's combined diff in
# `git log --cc` output. Its hunk header carries one `@` more than the merge
# has parents (`@@@ -1 -1 +1,2 @@@` for two), and one old range per parent.
DIFF_HEADER_RE = re.compile(r"^diff --(?:git|cc|combined) ")
HUNK_RE = re.compile(r"^(@{2,}) (?:-\d+(?:,\d+)? )+\+(\d+)(?:,\d+)? \1(?:\s|$)")

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

    In a merge commit's combined diff each line opens with one mark per
    parent. Only a line marked `+` against every parent, one that no parent
    had, is yielded. A line one parent already had came from that parent.
    """
    path: str | None = None
    lineno = 0
    parents = 1
    in_header = True  # a plain unified diff opens with ---/+++, no diff --git
    for line in diff_text.split("\n"):
        if DIFF_HEADER_RE.match(line):
            path = None  # each file block starts clean; no cross-file bleed
            in_header = True
            continue
        if line.startswith("@@"):
            m = HUNK_RE.match(line)
            parents = len(m.group(1)) - 1 if m else 1
            lineno = int(m.group(2)) if m else 0
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
        marks = line[:parents]
        if len(marks) < parents or marks.strip("+- "):
            continue  # not a hunk line
        if "-" in marks:
            continue  # a line only a parent has; new-file line counter untouched
        if marks == "+" * parents:
            yield path, lineno, line[parents:]
        lineno += 1  # an added line, or context present; either is in the new file


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
    # --text: a NUL byte or a `-diff` attribute made git print "Binary files
    # differ" for a text file, and its lines were never scanned.
    # --no-ext-diff, --no-textconv: a diff.external command or a textconv
    # filter from the runner's config could rewrite the diff, or blank it.
    result = _git(
        root,
        "-c",
        "core.quotePath=false",
        "diff",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--text",
        "--unified=0",
        from_commit,
        to_commit,
    )
    if result.returncode != 0:
        raise DiffError(f"git diff failed: {_last_error_line(result)}")
    return _text(result.stdout)


def git_added_paths(from_commit: str, to_commit: str, root: str = ".") -> list[str]:
    """Return every path the range adds, or renames or copies a file to.

    Asked of git directly, because a binary file, an empty file and a pure
    rename add no line for the diff parser to take a name from. C is in the
    filter with A and R because diff.renames=copies reports a copy as C.
    """
    result = _git(
        root,
        "diff",
        "--no-color",
        "--no-ext-diff",
        "--name-only",
        "-z",
        "--diff-filter=ACR",
        from_commit,
        to_commit,
    )
    if result.returncode != 0:
        raise DiffError(f"git diff --name-only failed: {_last_error_line(result)}")
    return [name for name in _text(result.stdout).split("\0") if name]


def _blob_head(spec: str, root: str) -> bytes:
    """Return the first bytes of the blob spec names, or b"" if there is none."""
    with subprocess.Popen(
        ["git", "-C", root, "cat-file", "blob", spec],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ) as proc:
        head = proc.stdout.read(MEDIA_HEAD_BYTES) if proc.stdout else b""
        proc.kill()  # the rest of a large video is not needed
    return head


def media_at(commit: str, root: str = ".") -> Callable[[str], bool]:
    """Return a check for whether a path is real binary media as of commit.

    It takes a media name and, in the blob the commit holds for the path, the
    leading bytes of that format. A blob that cannot be read is not media, so
    its lines are scanned.
    """

    def check(path: str) -> bool:
        if media_extension(path) not in MEDIA_RE:
            return False
        return is_media(path, _blob_head(f"{commit}:{path}", root))

    return check


def _shallow_boundaries(root: str) -> set[str]:
    """Return the commits a shallow clone cuts history off at, or none."""
    shallow = _git(root, "rev-parse", "--is-shallow-repository")
    if _text(shallow.stdout).strip() != "true":
        return set()
    where = _text(_git(root, "rev-parse", "--git-path", "shallow").stdout).strip()
    try:
        return set((Path(root) / where).read_text(encoding="ascii").split())
    except OSError as exc:
        raise DiffError(
            f"this clone is shallow and its list of cut-off commits is unreadable ({exc})."
        ) from exc


def commits_in_range(from_commit: str, to_commit: str, root: str = ".") -> list[str]:
    result = _git(root, "rev-list", f"{from_commit}..{to_commit}")
    if result.returncode != 0:
        raise DiffError(
            f"cannot list the commits in {from_commit[:12]}..{to_commit[:12]}: "
            f"{_last_error_line(result)}"
        )
    return _text(result.stdout).split()


def require_visible_commits(
    from_commit: str, to_commit: str, root: str = "."
) -> list[str]:
    """Return the commits in from..to once none of them hides its parents.

    A commit on a shallow clone's boundary has parents the clone lacks, so
    earlier commits of the range may sit behind it out of view. Their history
    is then fetched from origin in full, once. A fetch limited by depth would
    not do: it writes a new boundary even on a commit whose parents the clone
    already has, which cuts the base branch's history off and puts the base's
    own commits in the range. If a boundary is still in the range, DiffError
    says so rather than letting the scan read fewer commits than it holds.
    """
    commits = commits_in_range(from_commit, to_commit, root)
    boundaries = _shallow_boundaries(root)
    cut = [sha for sha in commits if sha in boundaries]
    detail = ""
    if cut:
        fetch = _git(root, "fetch", "--no-tags", "--unshallow", "origin", *cut)
        if fetch.returncode:
            detail = f" Fetching their history failed: {_last_error_line(fetch)}"
        commits = commits_in_range(from_commit, to_commit, root)
        boundaries = _shallow_boundaries(root)
        cut = [sha for sha in commits if sha in boundaries]
    if cut:
        raise DiffError(
            f"{len(cut)} commit(s) in {from_commit[:12]}..{to_commit[:12]}, such as "
            f"{cut[0][:12]}, sit on this shallow clone's boundary, so commits "
            "before them are out of view and cannot be scanned. Check out with "
            f"fetch-depth: 0.{detail}"
        )
    return commits


def _git_log(root: str, from_commit: str, to_commit: str, *output: str) -> str:
    """Run `git log` over from..to, oldest commit first, each opened by a marker.

    --cc gives a merge commit its combined diff, which shows the lines no
    parent had. --root keeps a parentless commit's patch whatever log.showRoot
    says. The diff flags match git_diff's.
    """
    result = _git(
        root,
        "-c",
        "core.quotePath=false",
        "log",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--root",
        "--cc",
        "--topo-order",
        "--reverse",
        "--format=%x00%H",
        *output,
        f"{from_commit}..{to_commit}",
    )
    if result.returncode != 0:
        raise DiffError(f"git log failed: {_last_error_line(result)}")
    return _text(result.stdout)


def _split_log(log_text: str) -> list[tuple[str, str]]:
    """Split _git_log output into (commit, body) pairs.

    Each commit opens with a line that starts with a NUL byte. No diff line
    can: every one starts with a mark or a header word.
    """
    commits = []
    for chunk in ("\n" + log_text).split("\n\0")[1:]:
        sha, _, body = chunk.partition("\n")
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", sha):
            raise DiffError(
                f"git log printed an unreadable commit marker: {sha[:40]!r}"
            )
        commits.append((sha, body))
    return commits


def git_commit_patches(
    from_commit: str, to_commit: str, root: str = "."
) -> list[tuple[str, str]]:
    """Return (commit, patch) for each commit in from..to, oldest first."""
    log = _git_log(root, from_commit, to_commit, "-p", "--text", "--unified=0")
    return _split_log(log)


def git_commit_added_paths(
    from_commit: str, to_commit: str, root: str = "."
) -> dict[str, list[str]]:
    """Return, for each commit in from..to, the paths it adds, renames or copies to.

    For a merge commit, only a path that none of its parents had.
    """
    log = _git_log(root, from_commit, to_commit, "--name-status")
    added: dict[str, list[str]] = {}
    for sha, body in _split_log(log):
        paths = added.setdefault(sha, [])
        for line in body.split("\n"):
            status, _, names = line.partition("\t")
            if not names:
                continue
            letters = status.rstrip("0123456789")  # R100, C75: similarity score
            if len(letters) == 1:
                new = letters in ("A", "C", "R")
            else:  # a merge: one letter per parent, A where that parent lacks it
                new = bool(letters) and set(letters) == {"A"}
            if new:
                paths.append(unquote_header_path(names.split("\t")[-1]))
    return added


def scan_commits(
    from_commit: str,
    to_commit: str,
    root: str = ".",
    extra_patterns: Iterable[tuple[str, re.Pattern[str]]] = (),
    skip_paths: Collection[str] = frozenset(),
) -> tuple[list[Finding], int]:
    """Scan each commit in from..to on its own, oldest first.

    A line one commit adds and a later one removes never shows in the net
    diff, but the commit that added it stays in the branch's history, which
    is public once pushed, and a merge commit or a rebase merge carries it
    onto the base branch. Returns the findings, each naming its commit, and
    the number of commits in the range.
    """
    commits = require_visible_commits(from_commit, to_commit, root)
    patches = git_commit_patches(from_commit, to_commit, root)
    if sorted(sha for sha, _ in patches) != sorted(commits):
        raise DiffError(
            f"git log did not print every commit in {from_commit[:12]}..{to_commit[:12]}, "
            "so they could not all be scanned."
        )
    added = git_commit_added_paths(from_commit, to_commit, root)
    findings = []
    for sha, patch in patches:
        paths = added.get(sha, ())
        media = media_at(sha, root)
        for f in scan_added_lines(patch, extra_patterns, paths, skip_paths, media):
            findings.append(replace(f, commit=sha))
    return findings, len(commits)


def merge_findings(net: list[Finding], history: list[Finding]) -> list[Finding]:
    """Add each commit finding the net diff does not already report.

    A value the net diff reports is still in the change, and that finding
    already blocks it. Any other value is reported once, at the earliest
    commit that added it, since that commit is what keeps it in history.
    """
    reported = {(f.label, f.masked) for f in net}
    first_commit: dict[tuple[str, str], str] = {}
    merged = list(net)
    for f in history:
        key = (f.label, f.masked)
        if key in reported:
            continue
        if first_commit.setdefault(key, f.commit) == f.commit:
            merged.append(f)
    return merged


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
    diff_text: str,
    extra_patterns: Iterable[tuple[str, re.Pattern[str]]] = (),
    added_paths: Iterable[str] = (),
    skip_paths: Collection[str] = frozenset(),
    is_media_file: Callable[[str], bool] | None = None,
) -> list[Finding]:
    """Scan a diff's added lines, and the name of each file it adds to.

    added_paths (see git_added_paths) names the files the range adds or
    renames. Each gets the filename check even when the diff shows no line
    for it, as with a binary file, an empty file or a pure rename. Paths in
    skip_paths are not scanned at all. is_media_file (see media_at) says
    which paths are real binary media, whose lines are skipped. Without it
    every line is scanned, since a diff does not show a file's leading bytes.
    """
    findings: list[Finding] = []
    seen_paths: set[str] = set()
    media_paths: set[str] = set()
    for path, lineno, text in parse_added_lines(diff_text):
        if path in skip_paths:
            continue
        if path not in seen_paths:
            seen_paths.add(path)
            label = check_filename(path)
            if label:
                findings.append(Finding(path, lineno, label, mask(path)))
            if is_media_file and is_media_file(path):
                media_paths.add(path)
        if path in media_paths:
            continue
        for hit_label, matched in scan_line(text, extra_patterns):
            findings.append(Finding(path, lineno, hit_label, mask(matched)))
    for path in added_paths:
        if path in skip_paths or path in seen_paths:
            continue
        seen_paths.add(path)
        label = check_filename(path)
        if label:
            findings.append(Finding(path, 1, label, mask(path)))
    return findings


def scan_all_files(
    root: str = ".",
    extra_patterns: Iterable[tuple[str, re.Pattern[str]]] = (),
    skip_paths: Collection[str] = frozenset(),
) -> list[Finding]:
    findings: list[Finding] = []
    root_path = Path(root)
    for rel_path in iter_tracked_files(root):
        if rel_path in skip_paths:
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


def command_data(text: str) -> str:
    """Escape text for a workflow command's message, as @actions/core does.

    A raw newline ends the command, and the runner reads whatever follows it
    as a line of its own. A file name that carried one forged a warning and
    a ::stop-commands::, which silenced every real finding after it.
    """
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def command_property(text: str) -> str:
    """Escape text for a workflow command property, such as file=."""
    return command_data(text).replace(":", "%3A").replace(",", "%2C")


def report(findings: list[Finding], fail_on: str) -> int:
    level = "error" if fail_on == "match" else "warning"
    for f in findings:
        if f.commit:
            message = (
                f"Possible {f.label} added in commit {f.commit[:12]}: {f.masked} "
                f"(masked, not the real value). A later commit that removes it "
                f"leaves it in the branch's history, so rewrite the branch without "
                f"it, or mark the line in that commit with `{SUPPRESS_MARKER}` if "
                f"it is a deliberate placeholder."
            )
        else:
            message = (
                f"Possible {f.label}: {f.masked} (masked, not the real value). "
                f"Generalise or remove before this can merge, or mark the line "
                f"with `{SUPPRESS_MARKER}` if it is a deliberate placeholder."
            )
        print(
            f"::{level} file={command_property(f.path)},line={f.line}::"
            f"{command_data(message)}"
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
    # A finding's path can hold any character, and a Windows runner's stdout
    # is cp1252. Escape what the stream cannot encode instead of crashing
    # halfway through the report.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            reconfigure(errors="backslashreplace")
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
        "--skip-scanner-files",
        action="store_true",
        help="skip redaction_check.py and test_redaction_check.py at the repo root, "
        "whose test fixtures are secret-shaped on purpose. For this action's own "
        "repository: anywhere else, files with those names are scanned as usual",
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
    skip_paths = SELF_PATHS if args.skip_scanner_files else frozenset()

    if args.mode == "all-files":
        findings = scan_all_files(args.root, extra_patterns, skip_paths)
    else:
        added_paths: list[str] = []
        history: list[Finding] = []
        is_media_file = None
        if args.base:
            try:
                from_commit, to_commit, how = resolve_diff_range(
                    args.base, args.root, args.pr_head
                )
                diff_text = git_diff(from_commit, to_commit, args.root)
                added_paths = git_added_paths(from_commit, to_commit, args.root)
                is_media_file = media_at(to_commit, args.root)
                history, commit_count = scan_commits(
                    from_commit, to_commit, args.root, extra_patterns, skip_paths
                )
            except DiffError as exc:
                reason = f"Redaction gate cannot compute the diff to scan. {exc}"
                print(f"::error::{command_data(reason)}")
                return 2
            print(
                f"Scanning lines added in {from_commit[:12]}..{to_commit[:12]} ({how}), "
                f"and in each of its {commit_count} commit(s) on its own."
            )
            if not diff_text.strip() and not commit_count:
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
        net = scan_added_lines(
            diff_text, extra_patterns, added_paths, skip_paths, is_media_file
        )
        findings = merge_findings(net, history)

    return report(findings, args.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
