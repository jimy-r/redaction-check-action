"""Offline unittests for redaction_check.py. No network: every git repository,
including the one that stands in for a remote, is a local temp directory.

Fake credential/path shapes below are built by string concatenation rather
than written as contiguous literals, so this file itself carries no string
an unrelated static scanner (GitHub push protection, a pre-commit hook) could
mistake for a real secret. See redaction_check.SELF_PATHS -- this file is
also excluded from the scanner's own findings for the same reason.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import redaction_check as rc

THIS_DIR = Path(__file__).resolve().parent


def run_main(argv: list[str], stdin_text: str | None = None) -> tuple[int, str, str]:
    """Call main() in-process, capturing stdout/stderr and exit code."""
    out, err = io.StringIO(), io.StringIO()
    patches = [contextlib.redirect_stdout(out), contextlib.redirect_stderr(err)]
    if stdin_text is not None:
        patches.append(mock.patch("sys.stdin", io.StringIO(stdin_text)))
    with contextlib.ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        code = rc.main(argv)
    return code, out.getvalue(), err.getvalue()


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------


class EmailTests(unittest.TestCase):
    def test_real_looking_address_is_flagged(self):
        hits = rc.scan_line("contact " + "real.person" + "@gmail.com" + " for details")
        self.assertEqual([label for label, _ in hits], ["email address"])

    def test_example_com_is_allowed(self):
        self.assertEqual(rc.scan_line("mail the author at user@example.com"), [])

    def test_dot_example_tld_is_allowed(self):
        self.assertEqual(rc.scan_line("see contact@service.example for details"), [])

    def test_other_rfc2606_reserved_tlds_are_allowed(self):
        # .test, .invalid, .localhost are reserved alongside .example (RFC
        # 2606) and are common in CI fixtures, e.g. `git config user.email`.
        for addr in ["ci@example.invalid", "bot@ci.test", "root@my.localhost"]:
            with self.subTest(addr=addr):
                self.assertEqual(rc.scan_line(f"git config user.email {addr}"), [])

    def test_github_noreply_is_allowed(self):
        self.assertEqual(
            rc.scan_line("Co-Authored-By: bot <1234+bot@users.noreply.github.com>"), []
        )

    def test_placeholder_domain_list_is_allowed(self):
        for domain in ["test.com", "domain.com", "company.com", "acme.com"]:
            with self.subTest(domain=domain):
                self.assertEqual(rc.scan_line(f"reach us at hello@{domain}"), [])


# ---------------------------------------------------------------------------
# Absolute home paths
# ---------------------------------------------------------------------------


class HomePathTests(unittest.TestCase):
    def test_posix_home_with_real_username_is_flagged(self):
        hits = rc.scan_line("config lives at /home/" + "prodserver7" + "/settings.json")
        self.assertEqual([label for label, _ in hits], ["absolute home path"])

    def test_posix_home_with_placeholder_is_allowed(self):
        self.assertEqual(rc.scan_line("see /home/alice/project for the example"), [])

    def test_macos_users_with_real_username_is_flagged(self):
        hits = rc.scan_line("dropped in /Users/" + "jsmith87" + "/Documents")
        self.assertEqual([label for label, _ in hits], ["absolute home path"])

    def test_windows_backslash_path_is_flagged(self):
        hits = rc.scan_line("C:" + "\\Users\\" + "jsmith87" + "\\notes")
        self.assertEqual([label for label, _ in hits], ["absolute home path"])

    def test_windows_forwardslash_path_is_flagged(self):
        hits = rc.scan_line("open " + "C:/Users/" + "jsmith87" + "/notes")
        self.assertEqual([label for label, _ in hits], ["absolute home path"])

    def test_windows_path_with_placeholder_is_allowed(self):
        self.assertEqual(rc.scan_line("use " + "C:/Users/alice/workspace"), [])

    def test_ci_runner_home_is_allowed(self):
        # GitHub-hosted runners check out to /home/runner -- extremely common
        # in example CI logs and must not trip the gate.
        self.assertEqual(rc.scan_line("workspace at /home/runner/work/repo"), [])

    def test_windows_runner_admin_home_is_allowed(self):
        self.assertEqual(rc.scan_line("temp dir " + "C:/Users/runneradmin/AppData"), [])


# ---------------------------------------------------------------------------
# Credential / token prefixes
# ---------------------------------------------------------------------------


class CredentialTests(unittest.TestCase):
    def test_anthropic_key(self):
        hits = rc.scan_line("token " + "sk-ant-" + "api03EXAMPLEKEY0000000")
        self.assertEqual([label for label, _ in hits], ["Anthropic API key"])

    def test_anthropic_key_is_not_double_counted_as_openai(self):
        # sk-ant-... breaks the OpenAI pattern's own 20-char alnum run at the
        # first hyphen after "ant", so only one finding should come back.
        hits = rc.scan_line("sk-ant-api03-" + "A" * 40)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0][0], "Anthropic API key")

    def test_openai_style_key(self):
        hits = rc.scan_line("export OPENAI_API_KEY=" + "sk-" + "A" * 30)
        self.assertEqual([label for label, _ in hits], ["OpenAI-style API key"])

    def test_aws_access_key(self):
        hits = rc.scan_line("key " + "AKIA" + "EXAMPLE000000000" + " here")
        self.assertEqual([label for label, _ in hits], ["AWS access key ID"])

    def test_github_token(self):
        hits = rc.scan_line("auth " + "ghp_" + "A" * 36)
        self.assertEqual([label for label, _ in hits], ["GitHub token"])

    def test_github_fine_grained_pat(self):
        hits = rc.scan_line("auth " + "github_pat_" + "A" * 30)
        self.assertEqual([label for label, _ in hits], ["GitHub token"])

    def test_slack_token(self):
        hits = rc.scan_line("bot token " + "xoxb-" + "1234567890" + "-abcdefghij")
        self.assertEqual([label for label, _ in hits], ["Slack token"])

    def test_google_api_key(self):
        hits = rc.scan_line("key " + "AIza" + "A" * 35)
        self.assertEqual([label for label, _ in hits], ["Google API key"])

    def test_stripe_key(self):
        hits = rc.scan_line("secret " + "sk_live_" + "A" * 20)
        self.assertEqual([label for label, _ in hits], ["Stripe API key"])

    def test_private_key_block(self):
        hits = rc.scan_line("-----BEGIN " + "RSA PRIVATE KEY" + "-----")
        self.assertEqual([label for label, _ in hits], ["Private key block"])

    def test_ordinary_prose_has_no_credential_hits(self):
        self.assertEqual(
            rc.scan_line("the sky is clear and the skiff sailed at ski-resort speed"),
            [],
        )


# ---------------------------------------------------------------------------
# Private / link-local IPs
# ---------------------------------------------------------------------------


class PrivateIPTests(unittest.TestCase):
    def test_10_range_is_flagged(self):
        hits = rc.scan_line("internal host at " + "10.20.30.40")
        self.assertEqual([label for label, _ in hits], ["private/link-local IP"])

    def test_172_16_range_is_flagged(self):
        hits = rc.scan_line("docker bridge " + "172.17.0.1")
        self.assertEqual([label for label, _ in hits], ["private/link-local IP"])

    def test_172_outside_range_is_not_flagged(self):
        # 172.15.x and 172.32.x fall outside the 172.16/12 RFC1918 block.
        self.assertEqual(rc.scan_line("public-looking " + "172.15.9.9"), [])
        self.assertEqual(rc.scan_line("public-looking " + "172.32.9.9"), [])

    def test_192_168_range_is_flagged(self):
        hits = rc.scan_line("router at " + "192.168.1.42")
        self.assertEqual([label for label, _ in hits], ["private/link-local IP"])

    def test_169_254_link_local_is_flagged(self):
        hits = rc.scan_line("self-assigned " + "169.254.3.4")
        self.assertEqual([label for label, _ in hits], ["private/link-local IP"])

    def test_loopback_is_never_flagged(self):
        self.assertEqual(rc.scan_line("loopback is 127.0.0.1 in every stack"), [])
        self.assertEqual(rc.scan_line("also fine: 127.55.0.9"), [])

    def test_cloud_metadata_endpoint_is_allowed(self):
        self.assertEqual(rc.scan_line("curl 169.254.169.254/latest/meta-data"), [])


# ---------------------------------------------------------------------------
# mDNS / .local hostnames
# ---------------------------------------------------------------------------


class LocalHostnameTests(unittest.TestCase):
    def test_real_looking_hostname_is_flagged(self):
        hits = rc.scan_line("reachable at " + "build7.local" + " on the LAN")
        self.assertEqual([label for label, _ in hits], ["mDNS/.local hostname"])

    def test_placeholder_hostname_is_allowed(self):
        self.assertEqual(rc.scan_line("point mdns at myhost.local for testing"), [])

    def test_localhost_local_is_allowed(self):
        self.assertEqual(rc.scan_line("bind to localhost.local in dev"), [])

    def test_local_segment_before_a_config_extension_is_not_a_hostname(self):
        # Claude Code's per-user settings.local.json was the false positive
        # that forced a redaction-ok marker onto real docs. Every config
        # extension the lookahead exempts is covered here.
        for name in [
            "settings.local.json",
            ".claude/settings.local.json",
            "docker-compose.local.yml",
            "compose.local.yaml",
            "config.local.toml",
            "php.local.ini",
            "compose.local.env",
            "webpack.local.js",
            "vite.local.ts",
            "logback.local.xml",
            "application.local.properties",
        ]:
            with self.subTest(name=name):
                self.assertEqual(rc.scan_line(f"copy {name} over the defaults"), [])

    def test_host_inside_any_other_file_name_is_flagged(self):
        # A certificate, a vhost file or a log named after the machine
        # carries its hostname. Only config extensions are exempt.
        for line in [
            "ssl_certificate /etc/ssl/" + "devbox.local" + ".pem;",
            "include sites-enabled/" + "devbox.local" + ".conf;",
            "tail /var/log/app/user@" + "devbox.local" + ".log",
        ]:
            with self.subTest(line=line):
                labels = [label for label, _ in rc.scan_line(line)]
                self.assertIn("mDNS/.local hostname", labels)

    def test_hostname_followed_by_punctuation_is_still_flagged(self):
        # The lookahead only skips `.local.` before a config extension, so
        # a full stop or a port does not hide a host.
        for line in [
            "the share lives on " + "build7.local" + ".",
            "the share lives on " + "build7.local" + ". Mount it first.",
            "mount it from " + "build7.local" + ":/srv/share",
        ]:
            with self.subTest(line=line):
                hits = rc.scan_line(line)
                self.assertEqual([label for label, _ in hits], ["mDNS/.local hostname"])


# ---------------------------------------------------------------------------
# Secret-like filenames (checked once per file, not per line)
# ---------------------------------------------------------------------------


class SecretFilenameTests(unittest.TestCase):
    def test_dotenv_is_flagged(self):
        self.assertEqual(rc.check_filename(".env"), "dotenv file")

    def test_dotenv_variant_is_flagged(self):
        self.assertEqual(rc.check_filename(".env.production"), "dotenv file")

    def test_dotenv_example_is_exempt(self):
        self.assertIsNone(rc.check_filename(".env.example"))

    def test_dotenv_sample_and_template_are_exempt(self):
        self.assertIsNone(rc.check_filename(".env.sample"))
        self.assertIsNone(rc.check_filename(".env.template"))

    def test_unrelated_dotted_name_is_not_flagged(self):
        self.assertIsNone(rc.check_filename(".environment"))

    def test_ssh_private_key_is_flagged(self):
        self.assertEqual(rc.check_filename("id_rsa"), "SSH private key file")
        self.assertEqual(rc.check_filename("id_ed25519"), "SSH private key file")

    def test_ssh_public_key_is_not_flagged(self):
        self.assertIsNone(rc.check_filename("id_rsa.pub"))

    def test_pem_and_key_files_are_flagged(self):
        self.assertEqual(rc.check_filename("server.pem"), "key/cert file")
        self.assertEqual(rc.check_filename("client.key"), "key/cert file")

    def test_pem_example_is_exempt(self):
        self.assertIsNone(rc.check_filename("server.pem.example"))

    def test_credentials_json_is_flagged(self):
        self.assertEqual(rc.check_filename("credentials.json"), "credentials file")

    def test_service_account_json_is_flagged(self):
        self.assertEqual(rc.check_filename("service-account.json"), "credentials file")
        self.assertEqual(
            rc.check_filename("service_account_prod.json"), "credentials file"
        )

    def test_word_containing_credentials_is_not_flagged(self):
        self.assertIsNone(rc.check_filename("noncredentials.txt"))

    def test_netrc_pgpass_npmrc_are_flagged(self):
        self.assertEqual(rc.check_filename(".netrc"), "netrc file")
        self.assertEqual(rc.check_filename(".pgpass"), "pgpass file")
        self.assertEqual(rc.check_filename(".npmrc"), "npmrc file")

    def test_secrets_yaml_json_toml_are_flagged(self):
        self.assertEqual(rc.check_filename("secrets.yaml"), "secrets file")
        self.assertEqual(rc.check_filename("secrets.json"), "secrets file")
        self.assertEqual(rc.check_filename("secrets.toml"), "secrets file")

    def test_secrets_py_is_not_flagged(self):
        # Deliberately excluded: colliding with the stdlib `secrets` module
        # name is too common a legitimate filename to flag by shape alone.
        self.assertIsNone(rc.check_filename("secrets.py"))

    def test_ordinary_file_is_not_flagged(self):
        self.assertIsNone(rc.check_filename("README.md"))

    def test_nested_path_uses_basename_only(self):
        self.assertEqual(rc.check_filename("config/prod/.env"), "dotenv file")
        self.assertIsNone(rc.check_filename("config/prod/.env.example"))


# ---------------------------------------------------------------------------
# Suppression marker
# ---------------------------------------------------------------------------


class MediaSignatureTests(unittest.TestCase):
    def test_media_needs_its_format_s_leading_bytes(self):
        self.assertTrue(rc.is_media("img/logo.PNG", b"\x89PNG\r\n\x1a\n\x00\x00"))
        self.assertTrue(rc.is_media("clip.mp4", b"\x00\x00\x00\x20ftypisom"))
        self.assertTrue(rc.is_media("song.wav", b"RIFF\x24\x08\x00\x00WAVEfmt "))
        self.assertFalse(rc.is_media("notes.png", b"host " + IP.encode()))
        self.assertFalse(rc.is_media("song.wav", b"RIFF\x24\x08\x00\x00AVI "))
        self.assertFalse(rc.is_media("logo.jpg", b"\x89PNG\r\n\x1a\n"))
        self.assertFalse(rc.is_media("README", b"\x89PNG\r\n\x1a\n"))

    def test_an_uncompressed_tar_is_never_media(self):
        self.assertNotIn("tar", rc.MEDIA_RE)
        self.assertFalse(rc.is_media("backup.tar", b"cfg/notes.txt\x00\x00"))


class SuppressionMarkerTests(unittest.TestCase):
    def test_marker_suppresses_an_otherwise_flagged_line(self):
        line = "contact " + "real.person" + "@gmail.com" + "  # redaction-ok"
        self.assertEqual(rc.scan_line(line), [])

    def test_marker_absent_still_flags(self):
        line = "contact " + "real.person" + "@gmail.com"
        self.assertNotEqual(rc.scan_line(line), [])

    def test_marker_does_not_suppress_unrelated_lines(self):
        # The marker only reaches the physical line it's on.
        clean = "this line has redaction-ok but no finding anyway"
        self.assertEqual(rc.scan_line(clean), [])
        dirty = "contact " + "real.person" + "@gmail.com" + " (no marker here)"
        self.assertNotEqual(rc.scan_line(dirty), [])


# ---------------------------------------------------------------------------
# Masking -- the non-negotiable guarantee
# ---------------------------------------------------------------------------


class MaskingTests(unittest.TestCase):
    SECRETS = [
        "real.person" + "@gmail.com",
        "/home/" + "prodserver7" + "/config",
        "sk-ant-" + "api03EXAMPLEKEY0000000",
        "AKIA" + "EXAMPLE000000000",
        "10.20.30.40",
        "build7" + ".local",
    ]

    def test_mask_never_returns_the_input(self):
        for secret in self.SECRETS:
            with self.subTest(secret=secret):
                self.assertNotIn(secret, rc.mask(secret))

    def test_mask_output_contains_no_substring_of_the_input(self):
        # Stronger than equality: no 6+ char run of the secret should survive
        # into the masked output, ruling out partial-prefix leaks too.
        for secret in self.SECRETS:
            chunk = secret[:6]
            with self.subTest(secret=secret):
                self.assertNotIn(chunk.lower(), rc.mask(secret).lower())

    def test_mask_is_deterministic(self):
        secret = "sk-ant-" + "api03EXAMPLEKEY0000000"
        self.assertEqual(rc.mask(secret), rc.mask(secret))

    def test_mask_differs_for_different_secrets(self):
        self.assertNotEqual(rc.mask(self.SECRETS[0]), rc.mask(self.SECRETS[1]))

    def test_mask_is_not_a_plain_hash_of_the_secret(self):
        # An unsalted hash was reversible from the log alone: hashing 10/8
        # recovered a masked private IP in about two seconds.
        for secret in self.SECRETS:
            with self.subTest(secret=secret):
                plain = hashlib.sha256(secret.encode()).hexdigest()
                self.assertNotIn(plain[:12], rc.mask(secret))

    def test_each_run_masks_with_a_fresh_key(self):
        code = f"import redaction_check as rc; print(rc.mask({IP!r}))"
        tags = {
            subprocess.run(
                [sys.executable, "-c", code],
                cwd=THIS_DIR,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            for _ in range(2)
        }
        self.assertEqual(len(tags), 2, tags)
        self.assertTrue(all(re.fullmatch(r"hmac:[0-9a-f]{12}", t) for t in tags))

    def test_findings_from_scan_added_lines_never_contain_the_raw_secret(self):
        diff = (
            "diff --git a/notes.txt b/notes.txt\n"
            "index 111..222 100644\n"
            "--- a/notes.txt\n"
            "+++ b/notes.txt\n"
            "@@ -0,0 +1,2 @@\n"
            "+contact " + "real.person" + "@gmail.com" + " about the key\n"
            "+token " + "sk-ant-" + "api03EXAMPLEKEY0000000\n"
        )
        findings = rc.scan_added_lines(diff)
        self.assertTrue(findings)
        rendered = " ".join(f.masked for f in findings)
        for secret in [
            "real.person" + "@gmail.com",
            "sk-ant-" + "api03EXAMPLEKEY0000000",
        ]:
            self.assertNotIn(secret, rendered)

    def test_report_output_never_contains_the_raw_secret(self):
        diff = (
            "diff --git a/notes.txt b/notes.txt\n"
            "index 111..222 100644\n"
            "--- a/notes.txt\n"
            "+++ b/notes.txt\n"
            "@@ -0,0 +1,1 @@\n"
            "+key " + "AKIA" + "EXAMPLE000000000" + " in the open\n"
        )
        findings = rc.scan_added_lines(diff)
        out = io.StringIO()
        err = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc.report(findings, "match")
        combined = out.getvalue() + err.getvalue()
        self.assertNotIn("AKIA" + "EXAMPLE000000000", combined)


# ---------------------------------------------------------------------------
# Diff parsing -- built from real `git diff --unified=0` output (captured
# against a scratch repo), not hand-typed guesses, so hunk-header and marker
# shapes match what git actually emits.
# ---------------------------------------------------------------------------

DIFF_BINARY_ONLY = (
    "diff --git a/image.bin b/image.bin\n"
    "index b6b0538..5fbea0a 100644\n"
    "Binary files a/image.bin and b/image.bin differ\n"
)

DIFF_PURE_DELETE = (
    "diff --git a/rename_me.txt b/rename_me.txt\n"
    "deleted file mode 100644\n"
    "index e0808fa..0000000 100644\n"
    "--- a/rename_me.txt\n"
    "+++ /dev/null\n"
    "@@ -1 +0,0 @@\n"
    "-keep me\n"
)

# One multi-file diff covering: rename+edit, a text file with two separate
# hunks, a brand-new file, and a pure rename (100% similarity, no hunks).
# Also exercises the "\ No newline at end of file" marker on both sides of
# a hunk.
DIFF_MULTI_FILE = (
    "diff --git a/edit_old.txt b/edit_new.txt\n"
    "similarity index 61%\n"
    "rename from edit_old.txt\n"
    "rename to edit_new.txt\n"
    "index c94a4b0..5ccd254 100644\n"
    "--- a/edit_old.txt\n"
    "+++ b/edit_new.txt\n"
    "@@ -1,0 +2 @@ rename plus edit original\n"
    "+plus a new line\n"
    "diff --git a/note.bin b/note.bin\n"
    "index 701d2b5..257d1a7 100644\n"
    "--- a/note.bin\n"
    "+++ b/note.bin\n"
    "@@ -1 +1 @@\n"
    "-binary before\n"
    "\\ No newline at end of file\n"
    "+binary after CHANGED\n"
    "\\ No newline at end of file\n"
    "diff --git a/multi.txt b/multi.txt\n"
    "index 0c2aa38..a77df78 100644\n"
    "--- a/multi.txt\n"
    "+++ b/multi.txt\n"
    "@@ -2 +2 @@ line one\n"
    "-line two\n"
    "+NEW SECOND\n"
    "@@ -3,0 +4 @@ line three\n"
    "+added tail\n"
    "diff --git a/newfile.txt b/newfile.txt\n"
    "new file mode 100644\n"
    "index 0000000..4661944 100644\n"
    "--- /dev/null\n"
    "+++ b/newfile.txt\n"
    "@@ -0,0 +1,2 @@\n"
    "+brand new file\n"
    "+second added line\n"
    "diff --git a/pure_old.txt b/pure_new.txt\n"
    "similarity index 100%\n"
    "rename from pure_old.txt\n"
    "rename to pure_new.txt\n"
)


class DiffParsingTests(unittest.TestCase):
    def test_binary_file_yields_nothing(self):
        self.assertEqual(list(rc.parse_added_lines(DIFF_BINARY_ONLY)), [])

    def test_pure_delete_yields_nothing(self):
        self.assertEqual(list(rc.parse_added_lines(DIFF_PURE_DELETE)), [])

    def test_multi_file_diff_yields_expected_added_lines(self):
        got = list(rc.parse_added_lines(DIFF_MULTI_FILE))
        expected = [
            ("edit_new.txt", 2, "plus a new line"),
            ("note.bin", 1, "binary after CHANGED"),
            ("multi.txt", 2, "NEW SECOND"),
            ("multi.txt", 4, "added tail"),
            ("newfile.txt", 1, "brand new file"),
            ("newfile.txt", 2, "second added line"),
        ]
        self.assertEqual(got, expected)

    def test_pure_rename_contributes_no_added_lines(self):
        paths = {path for path, _, _ in rc.parse_added_lines(DIFF_MULTI_FILE)}
        self.assertNotIn("pure_new.txt", paths)
        self.assertNotIn("pure_old.txt", paths)

    def test_single_line_hunk_header_with_no_explicit_count(self):
        # "@@ -2 +2 @@" (no ",1") is git's real shape for a one-line hunk;
        # a parser that assumes the comma-count is always present breaks here.
        diff = (
            "diff --git a/f.txt b/f.txt\n"
            "index 1..2 100644\n"
            "--- a/f.txt\n"
            "+++ b/f.txt\n"
            "@@ -5 +5 @@\n"
            "-old\n"
            "+new\n"
        )
        self.assertEqual(list(rc.parse_added_lines(diff)), [("f.txt", 5, "new")])

    def test_context_lines_advance_lineno_without_being_yielded(self):
        # A diff with real context (unified > 0) should still parse the
        # correct line numbers for the added line among context lines.
        diff = (
            "diff --git a/f.txt b/f.txt\n"
            "index 1..2 100644\n"
            "--- a/f.txt\n"
            "+++ b/f.txt\n"
            "@@ -1,3 +1,4 @@\n"
            " line one\n"
            "+inserted\n"
            " line two\n"
            " line three\n"
        )
        self.assertEqual(list(rc.parse_added_lines(diff)), [("f.txt", 2, "inserted")])

    def test_new_file_hunk_starts_at_line_one(self):
        diff = (
            "diff --git a/new.txt b/new.txt\n"
            "new file mode 100644\n"
            "index 0000000..1111111 100644\n"
            "--- /dev/null\n"
            "+++ b/new.txt\n"
            "@@ -0,0 +1,1 @@\n"
            "+only line\n"
        )
        self.assertEqual(
            list(rc.parse_added_lines(diff)), [("new.txt", 1, "only line")]
        )

    def test_empty_diff_yields_nothing(self):
        self.assertEqual(list(rc.parse_added_lines("")), [])

    def test_combined_diff_yields_only_lines_no_parent_had(self):
        # `git log --cc` shows a merge commit this way, one mark per parent.
        # A line one parent already had came from that parent, not the merge.
        diff = (
            "diff --cc a.txt\n"
            "index 1111111,2222222..3333333\n"
            "--- a/a.txt\n"
            "+++ b/a.txt\n"
            "@@@ -4,0 -4,0 +4,3 @@@ three\n"
            "++only the merge added this\n"
            "+ the second parent had this\n"
            " +the first parent had this\n"
            "- -gone from both\n"
        )
        self.assertEqual(
            list(rc.parse_added_lines(diff)),
            [("a.txt", 4, "only the merge added this")],
        )

    def test_only_a_newline_ends_a_line(self):
        # splitlines() also broke at CR, form feed and U+2028, and the text
        # after each break lost its "+" and was never scanned.
        diff = (
            "diff --git a/f.txt b/f.txt\n"
            "--- a/f.txt\n"
            "+++ b/f.txt\n"
            "@@ -0,0 +1 @@\n"
            "+one\rtwo\fthree four\n"
        )
        self.assertEqual(
            list(rc.parse_added_lines(diff)), [("f.txt", 1, "one\rtwo\fthree four")]
        )

    def test_added_line_shaped_like_a_header_is_content(self):
        # A file whose first line is "++ /dev/null" shows up in a hunk as
        # "+++ /dev/null". Read as a header, it ended the file, and every
        # added line after it went unscanned.
        diff = (
            "diff --git a/pp.txt b/pp.txt\n"
            "new file mode 100644\n"
            "--- /dev/null\n"
            "+++ b/pp.txt\n"
            "@@ -0,0 +1,3 @@\n"
            "+++ /dev/null\n"
            "+++ b/elsewhere.txt\n"
            "+host " + "10.20.30.40" + "\n"
        )
        self.assertEqual(
            list(rc.parse_added_lines(diff)),
            [
                ("pp.txt", 1, "++ /dev/null"),
                ("pp.txt", 2, "++ b/elsewhere.txt"),
                ("pp.txt", 3, "host " + "10.20.30.40"),
            ],
        )

    def test_quoted_and_tab_suffixed_header_paths_are_decoded(self):
        # Git C-quotes a path with a non-ASCII byte (under the default
        # core.quotePath), a control character, a quote or a backslash, and
        # appends a tab to one with a space. Taken as printed, none of these
        # had a basename that matched `.env`.
        headers = {
            '"b/caf\\303\\251/.env"': "café/.env",
            "b/my dir/.env\t": "my dir/.env",
            '"b/tab\\there/quote\\"d\\\\dir/.env"': 'tab\there/quote"d\\dir/.env',
            '"b/two words\\001/.env"\t': "two words\x01/.env",
        }
        for header, path in headers.items():
            with self.subTest(header=header):
                diff = f"diff --git a/x b/x\n+++ {header}\n@@ -0,0 +1 @@\n+K=v\n"
                self.assertEqual(list(rc.parse_added_lines(diff)), [(path, 1, "K=v")])
                labels = [f.label for f in rc.scan_added_lines(diff)]
                self.assertEqual(labels, ["dotenv file"])

    def test_a_diff_saved_with_crlf_still_parses(self):
        diff = "diff --git a/.env b/.env\r\n--- /dev/null\r\n+++ b/.env\r\n@@ -0,0 +1 @@\r\n+K=v\r\n"
        got = [(path, lineno) for path, lineno, _ in rc.parse_added_lines(diff)]
        self.assertEqual(got, [(".env", 1)])


# ---------------------------------------------------------------------------
# Extra patterns file
# ---------------------------------------------------------------------------


class ExtraPatternsTests(unittest.TestCase):
    def test_extra_pattern_is_applied(self):
        with tempfile.TemporaryDirectory() as tmp:
            patterns_path = Path(tmp) / "patterns.txt"
            patterns_path.write_text("PROJECT-[0-9]{4}-INTERNAL\n", encoding="utf-8")
            extra = rc.load_extra_patterns(str(patterns_path))
            hits = rc.scan_line("ticket PROJECT-1234-INTERNAL needs review", extra)
            self.assertEqual(len(hits), 1)
            self.assertTrue(hits[0][0].startswith("custom pattern"))

    def test_comments_and_blank_lines_are_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            patterns_path = Path(tmp) / "patterns.txt"
            patterns_path.write_text(
                "# a comment\n\n   \nFOO-BAR-[0-9]+\n", encoding="utf-8"
            )
            extra = rc.load_extra_patterns(str(patterns_path))
            self.assertEqual(len(extra), 1)

    def test_invalid_regex_raises_a_clear_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            patterns_path = Path(tmp) / "patterns.txt"
            patterns_path.write_text("([unclosed\n", encoding="utf-8")
            with self.assertRaises(SystemExit) as ctx:
                rc.load_extra_patterns(str(patterns_path))
            self.assertIn("invalid regex", str(ctx.exception))

    def test_extra_patterns_do_not_affect_lines_without_a_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            patterns_path = Path(tmp) / "patterns.txt"
            patterns_path.write_text("INTERNAL-CODE-[0-9]+\n", encoding="utf-8")
            extra = rc.load_extra_patterns(str(patterns_path))
            self.assertEqual(rc.scan_line("nothing interesting here", extra), [])


# ---------------------------------------------------------------------------
# Scan drivers (added-lines / all-files) end to end
# ---------------------------------------------------------------------------


class ScanAddedLinesTests(unittest.TestCase):
    def test_nul_bytes_between_characters_do_not_hide_a_match(self):
        self.assertEqual(
            rc.scan_line("\x00".join(f"host {IP}")),
            [("private/link-local IP", IP)],
        )

    def test_new_dotenv_file_is_flagged_once_not_per_line(self):
        diff = (
            "diff --git a/.env b/.env\n"
            "new file mode 100644\n"
            "index 0000000..1111111 100644\n"
            "--- /dev/null\n"
            "+++ b/.env\n"
            "@@ -0,0 +1,2 @@\n"
            "+API_KEY=x\n"
            "+DB_PASSWORD=y\n"
        )
        findings = rc.scan_added_lines(diff)
        filename_hits = [f for f in findings if f.label == "dotenv file"]
        self.assertEqual(len(filename_hits), 1)

    SCANNER_FILE_DIFF = (
        "diff --git a/test_redaction_check.py b/test_redaction_check.py\n"
        "index 1..2 100644\n"
        "--- a/test_redaction_check.py\n"
        "+++ b/test_redaction_check.py\n"
        "@@ -0,0 +1,1 @@\n"
        "+token " + "sk-ant-" + "api03EXAMPLEKEY0000000\n"
    )

    def test_files_named_like_the_scanner_are_scanned_by_default(self):
        # These names were skipped unasked, so a consumer's own file called
        # test_redaction_check.py passed whatever it held.
        labels = [f.label for f in rc.scan_added_lines(self.SCANNER_FILE_DIFF)]
        self.assertEqual(labels, ["Anthropic API key"])

    def test_scanner_files_are_skipped_only_when_asked(self):
        skipped = rc.scan_added_lines(self.SCANNER_FILE_DIFF, (), (), rc.SELF_PATHS)
        self.assertEqual(skipped, [])
        nested = self.SCANNER_FILE_DIFF.replace("test_redaction_check.py", "sub/x.py")
        self.assertTrue(rc.scan_added_lines(nested, (), (), rc.SELF_PATHS))

    def test_cli_skips_scanner_files_only_with_the_flag(self):
        for argv, expected in [([], 1), (["--skip-scanner-files"], 0)]:
            with self.subTest(argv=argv):
                code, _out, _err = run_main(
                    ["--diff-file", "-", *argv], stdin_text=self.SCANNER_FILE_DIFF
                )
                self.assertEqual(code, expected)

    def test_added_paths_get_the_filename_check_once(self):
        diff = (
            "diff --git a/.env b/.env\n--- /dev/null\n+++ b/.env\n@@ -0,0 +1 @@\n+K=v\n"
        )
        added = [".env", "keys/id_rsa", "notes.txt", "redaction_check.py"]
        found = [(f.path, f.label) for f in rc.scan_added_lines(diff, (), added)]
        self.assertEqual(
            found, [(".env", "dotenv file"), ("keys/id_rsa", "SSH private key file")]
        )

    def test_clean_diff_produces_no_findings(self):
        diff = (
            "diff --git a/f.txt b/f.txt\n"
            "index 1..2 100644\n"
            "--- a/f.txt\n"
            "+++ b/f.txt\n"
            "@@ -0,0 +1,1 @@\n"
            "+nothing sensitive about this line at all\n"
        )
        self.assertEqual(rc.scan_added_lines(diff), [])


class ScanAllFilesTests(unittest.TestCase):
    def test_walks_tracked_files_and_finds_a_planted_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q"], cwd=tmp, check=True)
            clean = Path(tmp) / "clean.txt"
            clean.write_text("nothing sensitive here\n", encoding="utf-8")
            dirty = Path(tmp) / "dirty.txt"
            dirty.write_text("internal host " + "10.20.30.40" + "\n", encoding="utf-8")
            subprocess.run(
                ["git", "add", "clean.txt", "dirty.txt"], cwd=tmp, check=True
            )
            findings = rc.scan_all_files(tmp)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].path, "dirty.txt")

    def test_untracked_files_are_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q"], cwd=tmp, check=True)
            untracked = Path(tmp) / "untracked.txt"
            untracked.write_text(
                "internal host " + "10.20.30.40" + "\n", encoding="utf-8"
            )
            findings = rc.scan_all_files(tmp)
            self.assertEqual(findings, [])

    def test_secret_filename_is_found_even_with_clean_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q"], cwd=tmp, check=True)
            envfile = Path(tmp) / ".env"
            envfile.write_text("PLACEHOLDER=1\n", encoding="utf-8")
            subprocess.run(["git", "add", ".env"], cwd=tmp, check=True)
            findings = rc.scan_all_files(tmp)
            self.assertEqual([f.label for f in findings], ["dotenv file"])

    def test_scanner_file_names_are_walked_unless_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q"], cwd=tmp, check=True)
            probe = Path(tmp) / "test_redaction_check.py"
            probe.write_text("HOST = '" + "10.20.30.40" + "'\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=tmp, check=True)
            walked = [f.path for f in rc.scan_all_files(tmp)]
            skipped = rc.scan_all_files(tmp, (), rc.SELF_PATHS)
        self.assertEqual(walked, ["test_redaction_check.py"])
        self.assertEqual(skipped, [])

    def test_secret_file_under_a_non_ascii_directory_is_found(self):
        # Plain `git ls-files` quoted this name, so it neither matched a
        # secret filename nor opened for the content scan.
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q"], cwd=tmp, check=True)
            envfile = Path(tmp) / "café" / ".env"
            envfile.parent.mkdir()
            envfile.write_text("HOST=" + "10.20.30.40" + "\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=tmp, check=True)
            found = [(f.path, f.label) for f in rc.scan_all_files(tmp)]
        self.assertEqual(
            found,
            [("café/.env", "dotenv file"), ("café/.env", "private/link-local IP")],
        )


# ---------------------------------------------------------------------------
# CLI / exit codes
# ---------------------------------------------------------------------------


class CLITests(unittest.TestCase):
    def test_clean_diff_exits_zero(self):
        diff = (
            "diff --git a/f.txt b/f.txt\n"
            "index 1..2 100644\n"
            "--- a/f.txt\n"
            "+++ b/f.txt\n"
            "@@ -0,0 +1,1 @@\n"
            "+nothing sensitive here\n"
        )
        code, out, _err = run_main(["--diff-file", "-"], stdin_text=diff)
        self.assertEqual(code, 0)
        self.assertIn("clean", out)

    def test_dirty_diff_exits_one_by_default(self):
        diff = (
            "diff --git a/f.txt b/f.txt\n"
            "index 1..2 100644\n"
            "--- a/f.txt\n"
            "+++ b/f.txt\n"
            "@@ -0,0 +1,1 @@\n"
            "+token " + "sk-ant-" + "api03EXAMPLEKEY0000000\n"
        )
        code, out, _err = run_main(["--diff-file", "-"], stdin_text=diff)
        self.assertEqual(code, 1)
        self.assertIn("::error", out)

    def test_fail_on_none_always_exits_zero(self):
        diff = (
            "diff --git a/f.txt b/f.txt\n"
            "index 1..2 100644\n"
            "--- a/f.txt\n"
            "+++ b/f.txt\n"
            "@@ -0,0 +1,1 @@\n"
            "+token " + "sk-ant-" + "api03EXAMPLEKEY0000000\n"
        )
        code, out, _err = run_main(
            ["--diff-file", "-", "--fail-on", "none"], stdin_text=diff
        )
        self.assertEqual(code, 0)
        self.assertIn("::warning", out)
        self.assertNotIn("::error", out)

    def test_stdin_is_read_when_no_diff_file_given(self):
        diff = (
            "diff --git a/f.txt b/f.txt\n"
            "index 1..2 100644\n"
            "--- a/f.txt\n"
            "+++ b/f.txt\n"
            "@@ -0,0 +1,1 @@\n"
            "+clean as can be\n"
        )
        code, _out, _err = run_main([], stdin_text=diff)
        self.assertEqual(code, 0)

    def test_patterns_file_argument_is_wired_through_the_cli(self):
        diff = (
            "diff --git a/f.txt b/f.txt\n"
            "index 1..2 100644\n"
            "--- a/f.txt\n"
            "+++ b/f.txt\n"
            "@@ -0,0 +1,1 @@\n"
            "+ticket PROJECT-9999-INTERNAL filed\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            patterns_path = Path(tmp) / "patterns.txt"
            patterns_path.write_text("PROJECT-[0-9]{4}-INTERNAL\n", encoding="utf-8")
            code, out, _err = run_main(
                ["--diff-file", "-", "--patterns-file", str(patterns_path)],
                stdin_text=diff,
            )
        self.assertEqual(code, 1)
        self.assertIn("custom pattern", out)

    CR_DIFF = (
        "diff --git a/f.txt b/f.txt\n"
        "--- a/f.txt\n"
        "+++ b/f.txt\n"
        "@@ -0,0 +1 @@\n"
        "+clean\rhost " + "10.20.30.40" + "\n"
    )

    def test_diff_file_is_read_without_newline_translation(self):
        # A text-mode read turned the CR into a line break, so the host
        # after it arrived without a "+" and was never scanned.
        with tempfile.TemporaryDirectory() as tmp:
            diff_path = Path(tmp) / "changes.diff"
            diff_path.write_bytes(self.CR_DIFF.encode("utf-8"))
            code, out, _err = run_main(["--diff-file", str(diff_path)])
        self.assertEqual(code, 1)
        self.assertIn("private/link-local IP", out)

    def test_stdin_is_read_without_newline_translation(self):
        result = subprocess.run(
            [sys.executable, str(THIS_DIR / "redaction_check.py")],
            input=self.CR_DIFF.encode("utf-8"),
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(b"private/link-local IP", result.stdout)

    def test_all_files_mode_via_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q"], cwd=tmp, check=True)
            dirty = Path(tmp) / "dirty.txt"
            dirty.write_text("internal host " + "10.20.30.40" + "\n", encoding="utf-8")
            subprocess.run(["git", "add", "dirty.txt"], cwd=tmp, check=True)
            code, out, _err = run_main(["--mode", "all-files", "--root", tmp])
        self.assertEqual(code, 1)
        self.assertIn("private/link-local IP", out)

    def test_a_path_the_output_encoding_lacks_does_not_crash_the_report(self):
        # Paths now print as they are, not git-quoted, and a Windows runner's
        # stdout is cp1252, which has no CJK characters.
        with tempfile.TemporaryDirectory() as tmp:
            repo = ScratchRepo(tmp)
            repo.write("日本/notes.md", ("host " + "10.20.30.40" + "\n").encode())
            repo.commit("add")
            result = subprocess.run(
                [sys.executable, str(THIS_DIR / "redaction_check.py")]
                + ["--base", "HEAD~1", "--root", tmp],
                capture_output=True,
                check=False,
                env={**os.environ, "PYTHONIOENCODING": "cp1252"},
            )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(b"private/link-local IP", result.stdout)
        self.assertNotIn(b"Traceback", result.stderr)


class WorkflowCommandTests(unittest.TestCase):
    """Findings print as ::error lines the runner parses. Nothing may break out."""

    def test_a_file_name_cannot_forge_workflow_commands(self):
        # Git C-quotes a path that holds a newline, and the parser decodes it.
        # Printed raw into file=, the rest of the name became lines of its
        # own: a forged warning, then a stop-commands that silenced every
        # real finding after it.
        name = "odd\n::warning title=INJECTED::forged\n::stop-commands::tok\nname.txt"
        quoted = '"b/' + name.replace("\n", "\\n") + '"'
        diff = (
            f"diff --git {quoted.replace('b/', 'a/', 1)} {quoted}\n"
            "new file mode 100644\n"
            "--- /dev/null\n"
            f"+++ {quoted}\n"
            "@@ -0,0 +1 @@\n"
            f"+host {IP}\n"
        )
        code, out, _err = run_main([], stdin_text=diff)
        self.assertEqual(code, 1)
        commands = [ln for ln in out.splitlines() if ln.startswith("::")]
        self.assertEqual(len(commands), 1)
        self.assertTrue(
            commands[0].startswith(
                "::error file=odd%0A%3A%3Awarning title=INJECTED%3A%3Aforged"
                "%0A%3A%3Astop-commands%3A%3Atok%0Aname.txt,line=1::Possible "
            ),
            commands[0],
        )

    def test_a_custom_pattern_label_is_escaped_in_the_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            patterns = Path(tmp) / "patterns.txt"
            patterns.write_text("TICKET%[0-9]+\n", encoding="utf-8")
            diff = (
                "diff --git a/n.txt b/n.txt\n"
                "--- /dev/null\n"
                "+++ b/n.txt\n"
                "@@ -0,0 +1 @@\n"
                "+see TICKET%42\n"
            )
            code, out, _err = run_main(
                ["--patterns-file", str(patterns)], stdin_text=diff
            )
        self.assertEqual(code, 1)
        self.assertIn("::Possible custom pattern (TICKET%25[0-9]+): ", out)

    def test_escaping_matches_the_actions_toolkit(self):
        self.assertEqual(rc.command_data("50% done\r\nnext"), "50%25 done%0D%0Anext")
        self.assertEqual(rc.command_property("a,b:c%\n.txt"), "a%2Cb%3Ac%25%0A.txt")


class GitOutputEncodingTests(unittest.TestCase):
    """A diff carrying bytes outside the host codepage must not crash the gate.

    Before the encoding fix, `text=True` alone decoded git's output with the
    Windows console codepage (cp1252) and a byte like 0x9d raised
    UnicodeDecodeError before any pattern ran — the gate failed on content it
    never scanned. Regression guard for that.
    """

    @staticmethod
    def _init_repo(tmp: str) -> None:
        subprocess.run(["git", "init", "-q"], cwd=tmp, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@example.com"], cwd=tmp, check=True
        )
        subprocess.run(["git", "config", "user.name", "test"], cwd=tmp, check=True)

    def test_diff_with_non_cp1252_bytes_is_scannable(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._init_repo(tmp)
            base = Path(tmp) / "base.txt"
            base.write_text("nothing here\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=tmp, check=True)
            subprocess.run(["git", "commit", "-qm", "base"], cwd=tmp, check=True)

            # 0x9d is undefined in cp1252. Written as raw bytes so the file is
            # not valid UTF-8 either — the harshest case for the decoder.
            (Path(tmp) / "odd.txt").write_bytes(
                b"internal host " + b"10.20.30.40" + b" caf\x9d\n"
            )
            subprocess.run(["git", "add", "-A"], cwd=tmp, check=True)
            subprocess.run(["git", "commit", "-qm", "odd"], cwd=tmp, check=True)

            diff = rc.get_diff_via_git("HEAD~1", root=tmp)
            self.assertIn("odd.txt", diff)
            findings = rc.scan_added_lines(diff)
            self.assertEqual([f.label for f in findings], ["private/link-local IP"])

    def test_tracked_filename_with_non_ascii_is_listed(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._init_repo(tmp)
            (Path(tmp) / "café.txt").write_text("clean\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=tmp, check=True)
            self.assertIn("caf", "".join(rc.iter_tracked_files(tmp)))


# ---------------------------------------------------------------------------
# Diff range -- a base branch that moves while the check is queued
# ---------------------------------------------------------------------------


def git_out(cwd: str | Path, *args: str) -> str:
    """Run git in cwd and return its stdout, failing the test on an error."""
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def checkout_merge(tmp: Path, url: str, merge: str, depth: int | None = None) -> str:
    """Check out a test-merge commit in a fresh clone, the way actions/checkout does."""
    runner = Path(tempfile.mkdtemp(dir=tmp))
    git_out(runner, "init", "-q")
    git_out(runner, "remote", "add", "origin", url)
    refspecs = [f"+{merge}:refs/remotes/pull/1/merge"]
    depth_args = []
    if depth is None:  # fetch-depth: 0 also fetches every branch
        refspecs.insert(0, "+refs/heads/*:refs/remotes/origin/*")
    else:
        depth_args = [f"--depth={depth}"]
    git_out(runner, "fetch", "-q", "--no-tags", *depth_args, "origin", *refspecs)
    git_out(runner, "checkout", "-q", "--detach", "refs/remotes/pull/1/merge")
    return str(runner)


class MovedBaseTests(unittest.TestCase):
    """A base branch that moves while the check is queued must not break the scan.

    The fixture models the failure seen in a consuming repository. GitHub
    builds the pull request's test-merge commit M on base tip T. The pull
    request is then squash-merged, so main moves to S, a child of T that M
    does not contain. The job checks out M with full history, and the action
    as shipped then ran `git fetch origin main --depth=1`. That fetch made S
    a history boundary, S and M shared no visible commit, and
    `git diff origin/main...HEAD` died with "no merge base" before a single
    line was scanned.
    """

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._tmp.cleanup)
        cls.tmp = Path(cls._tmp.name).resolve()
        up = cls.tmp / "upstream"
        up.mkdir()
        git_out(up, "init", "-q", "-b", "main")
        git_out(up, "config", "user.email", "test@example.com")
        git_out(up, "config", "user.name", "test")
        notes = up / "notes.txt"
        notes.write_text("first line\n", encoding="utf-8")
        git_out(up, "add", "notes.txt")
        git_out(up, "commit", "-qm", "T0")
        with notes.open("a", encoding="utf-8") as f:
            f.write("second line\n")
        git_out(up, "commit", "-qam", "T")
        cls.base_tip = git_out(up, "rev-parse", "HEAD")

        git_out(up, "checkout", "-q", "-b", "feature")
        with notes.open("a", encoding="utf-8") as f:
            f.write("internal host " + "10.20.30.40" + "\n")
        git_out(up, "commit", "-qam", "H")
        cls.pr_head = git_out(up, "rev-parse", "HEAD")

        # GitHub's test-merge commit: first parent T, second parent H.
        git_out(up, "checkout", "-q", "--detach", cls.base_tip)
        git_out(up, "merge", "-q", "--no-ff", "-m", "M", cls.pr_head)
        cls.merge = git_out(up, "rev-parse", "HEAD")
        git_out(up, "update-ref", "refs/pull/1/merge", cls.merge)

        # The pull request lands as a squash commit, so main moves on to S.
        git_out(up, "checkout", "-q", "main")
        git_out(up, "merge", "-q", "--squash", cls.pr_head)
        git_out(up, "commit", "-qm", "S")
        cls.url = up.as_uri()

    def checkout(self, depth: int | None = None) -> str:
        """Check out M in a fresh clone, the way actions/checkout does."""
        return checkout_merge(self.tmp, self.url, self.merge, depth)

    @staticmethod
    def shipped_refetch(runner: str) -> None:
        """The action's old fetch step, which grafted the moved base."""
        git_out(runner, "fetch", "-q", "origin", "main", "--depth=1")

    def test_fixture_reproduces_the_no_merge_base_failure(self):
        runner = self.checkout()
        self.shipped_refetch(runner)
        old = subprocess.run(
            ["git", "-C", runner, "diff", "--unified=0", "origin/main...HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(old.returncode, 128, old.stderr)

    def test_pr_head_diffs_the_merge_commit_against_its_first_parent(self):
        runner = self.checkout()
        git_out(runner, "fetch", "-q", "--no-tags", "origin", "main")
        frm, to, how = rc.resolve_diff_range("origin/main", runner, self.pr_head)
        self.assertEqual((frm, to), (self.base_tip, self.merge))
        self.assertIn("test-merge commit", how)

    def test_pr_head_survives_the_shipped_shallow_refetch(self):
        runner = self.checkout()
        self.shipped_refetch(runner)
        diff = rc.get_diff_via_git("origin/main", runner, self.pr_head)
        findings = rc.scan_added_lines(diff)
        self.assertEqual([f.label for f in findings], ["private/link-local IP"])

    def test_full_depth_refetch_keeps_the_merge_base(self):
        runner = self.checkout()
        git_out(runner, "fetch", "-q", "--no-tags", "origin", "main")
        frm, to, _how = rc.resolve_diff_range("origin/main", runner)
        self.assertEqual((frm, to), (self.base_tip, self.merge))

    def test_shallow_checkout_is_deepened_to_reach_the_first_parent(self):
        runner = self.checkout(depth=1)
        self.assertEqual(
            git_out(runner, "rev-parse", "--is-shallow-repository"), "true"
        )
        diff = rc.get_diff_via_git("origin/main", runner, self.pr_head)
        findings = rc.scan_added_lines(diff)
        self.assertEqual([f.label for f in findings], ["private/link-local IP"])

    def test_first_parent_that_cannot_be_fetched_is_a_clear_error(self):
        runner = self.checkout(depth=1)
        git_out(runner, "remote", "set-url", "origin", (self.tmp / "gone").as_uri())
        with self.assertRaises(rc.DiffError) as ctx:
            rc.resolve_diff_range("origin/main", runner, self.pr_head)
        self.assertIn("first parent", str(ctx.exception))

    def test_no_merge_base_is_a_clear_error(self):
        runner = self.checkout()
        self.shipped_refetch(runner)
        with self.assertRaises(rc.DiffError) as ctx:
            rc.resolve_diff_range("origin/main", runner)
        self.assertIn("no merge base", str(ctx.exception))
        self.assertIn("fetch-depth: 0", str(ctx.exception))

    def test_missing_base_is_a_clear_error(self):
        runner = self.checkout(depth=1)  # fetches the merge ref only
        with self.assertRaises(rc.DiffError) as ctx:
            rc.resolve_diff_range("origin/main", runner)
        self.assertIn("does not name a commit", str(ctx.exception))

    def checkout_base_tip(self, depth: int | None = None) -> str:
        """Check out main's tip, as pull_request_target does by default."""
        runner = Path(tempfile.mkdtemp(dir=self.tmp))
        git_out(runner, "init", "-q")
        git_out(runner, "remote", "add", "origin", self.url)
        if depth is None:  # every branch, so the pull request head is present
            args = ["origin", "+refs/heads/*:refs/remotes/origin/*"]
        else:
            args = [
                f"--depth={depth}",
                "origin",
                "+refs/heads/main:refs/remotes/origin/main",
            ]
        git_out(runner, "fetch", "-q", "--no-tags", *args)
        git_out(runner, "checkout", "-q", "--detach", "refs/remotes/origin/main")
        return str(runner)

    def test_checkout_without_the_pull_request_head_is_an_error(self):
        # The fallback used to diff the base branch against itself here and
        # report clean, whether or not the head commit was in the clone.
        for depth in [None, 1]:
            with self.subTest(depth=depth):
                runner = self.checkout_base_tip(depth)
                argv = ["--base", "origin/main", "--root", runner]
                code, out, _err = run_main([*argv, "--pr-head", self.pr_head])
                self.assertEqual(code, 2)
                self.assertIn("does not contain pull request head", out)
                self.assertNotIn("clean", out)

    def test_checkout_that_descends_from_the_pull_request_head_is_scanned(self):
        # A checkout of a head newer than the event's head.sha still holds it.
        runner = self.checkout()
        git_out(runner, "checkout", "-q", "--detach", self.pr_head)
        (Path(runner) / "later.txt").write_text("later\n", encoding="utf-8")
        git_out(runner, "add", "later.txt")
        identity = ["-c", "user.email=test@example.com", "-c", "user.name=test"]
        git_out(runner, *identity, "commit", "-qm", "later")
        frm, _to, how = rc.resolve_diff_range("origin/main", runner, self.pr_head)
        self.assertEqual(frm, self.base_tip)
        self.assertIn("merge base", how)

    def test_head_that_does_not_merge_pr_head_falls_back_to_the_merge_base(self):
        # A caller that checks out the pull request head itself, not the
        # merge ref, still gets the pull request's changes.
        runner = self.checkout()
        git_out(runner, "checkout", "-q", "--detach", self.pr_head)
        frm, to, how = rc.resolve_diff_range("origin/main", runner, self.pr_head)
        self.assertEqual((frm, to), (self.base_tip, self.pr_head))
        self.assertIn("merge base", how)

    def test_cli_scans_the_pull_request_after_the_base_moved(self):
        runner = self.checkout()
        self.shipped_refetch(runner)
        argv = ["--base", "origin/main", "--root", runner, "--pr-head", self.pr_head]
        code, out, _err = run_main(argv)
        self.assertEqual(code, 1)
        self.assertIn("Scanning lines added in", out)
        self.assertIn("private/link-local IP", out)

    def test_cli_never_passes_when_the_diff_cannot_be_computed(self):
        runner = self.checkout()
        self.shipped_refetch(runner)
        for fail_on in ["match", "none"]:
            with self.subTest(fail_on=fail_on):
                argv = ["--base", "origin/main", "--root", runner, "--fail-on", fail_on]
                code, out, _err = run_main(argv)
                self.assertEqual(code, 2)
                self.assertIn("::error::", out)
                self.assertNotIn("clean", out)

    def test_cli_says_so_when_the_range_is_empty(self):
        runner = self.checkout()
        code, out, _err = run_main(["--base", "HEAD", "--root", runner])
        self.assertEqual(code, 0)
        self.assertIn("::notice::", out)

    def test_cli_pr_head_needs_base(self):
        with self.assertRaises(SystemExit) as ctx:
            run_main(["--pr-head", self.pr_head])
        self.assertEqual(ctx.exception.code, 2)


class RewrittenBaseTests(unittest.TestCase):
    """A base branch force-pushed under a pull request must not narrow the scan.

    A private-IP leak lands on main in T, and a pull request branches from T
    with an innocuous commit H. GitHub builds the test merge M on T. Main is
    then force-pushed back to T0 plus a new commit B, which purges the leak,
    but the pull request still carries T, so merging it brings the leak back.
    M's first-parent range holds only H's change, so the scan has to widen to
    the merge base of the rewritten main and M.
    """

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._tmp.cleanup)
        cls.tmp = Path(cls._tmp.name).resolve()
        up = cls.tmp / "upstream"
        up.mkdir()
        git_out(up, "init", "-q", "-b", "main")
        git_out(up, "config", "user.email", "test@example.com")
        git_out(up, "config", "user.name", "test")
        (up / "a.txt").write_text("base\n", encoding="utf-8")
        git_out(up, "add", "-A")
        git_out(up, "commit", "-qm", "T0")
        cls.root_commit = git_out(up, "rev-parse", "HEAD")
        (up / "leak.txt").write_text("nas " + "10.20.30.40" + "\n", encoding="utf-8")
        git_out(up, "add", "-A")
        git_out(up, "commit", "-qm", "T: a leak lands on main")
        leaked_tip = git_out(up, "rev-parse", "HEAD")

        git_out(up, "checkout", "-q", "-b", "feature")
        (up / "f.txt").write_text("clean\n", encoding="utf-8")
        git_out(up, "add", "-A")
        git_out(up, "commit", "-qm", "H")
        cls.pr_head = git_out(up, "rev-parse", "HEAD")

        git_out(up, "checkout", "-q", "--detach", leaked_tip)
        git_out(up, "merge", "-q", "--no-ff", "-m", "M", cls.pr_head)
        cls.merge = git_out(up, "rev-parse", "HEAD")
        git_out(up, "update-ref", "refs/pull/5/merge", cls.merge)

        git_out(up, "checkout", "-q", "main")
        git_out(up, "reset", "-q", "--hard", cls.root_commit)
        (up / "o.txt").write_text("other\n", encoding="utf-8")
        git_out(up, "add", "-A")
        git_out(up, "commit", "-qm", "B: main rewritten, leak purged")
        cls.url = up.as_uri()

    def checkout(self, depth: int | None = None) -> str:
        """Check out M, then fetch the rewritten main as the action does."""
        runner = checkout_merge(self.tmp, self.url, self.merge, depth)
        git_out(runner, "fetch", "-q", "--no-tags", "origin", "main")
        return runner

    def scan(self, runner: str) -> tuple[int, str]:
        argv = ["--base", "origin/main", "--root", runner, "--pr-head", self.pr_head]
        code, out, _err = run_main(argv)
        return code, out

    def test_rewritten_base_widens_the_range_to_the_merge_base(self):
        runner = self.checkout()
        frm, to, how = rc.resolve_diff_range("origin/main", runner, self.pr_head)
        self.assertEqual((frm, to), (self.root_commit, self.merge))
        self.assertIn("rewritten", how)

    def test_cli_catches_the_leak_the_rewrite_purged_from_the_base(self):
        code, out = self.scan(self.checkout())
        self.assertEqual(code, 1)
        self.assertIn("file=leak.txt", out)

    def test_rewritten_base_without_history_to_widen_from_is_an_error(self):
        # At depth 1 the first parent arrives by deepening, as a shallow
        # boundary, so no merge base is visible. The base's own history is
        # complete, which proves the rewrite, so the gate refuses to pass.
        code, out = self.scan(self.checkout(depth=1))
        self.assertEqual(code, 2)
        self.assertIn("was rewritten", out)
        self.assertNotIn("clean", out)


# ---------------------------------------------------------------------------
# What reaches the parser: `git diff` output whatever the change holds or the
# runner's git config says
# ---------------------------------------------------------------------------

# (path, label) for every finding, whether or not it names a commit.
FINDING_RE = re.compile(
    r"^::error file=(.*),line=\d+::Possible (.+?)"
    r"(?: added in commit [0-9a-f]{12})?: hmac:",
    re.M,
)
# (path, label, short SHA) for the findings that come from one commit.
COMMIT_FINDING_RE = re.compile(
    r"^::error file=(.*),line=\d+::Possible (.+?) added in commit ([0-9a-f]{12}): ",
    re.M,
)
IP = "10.20.30.40"


class ScratchRepo:
    """A throwaway repository with one base commit; tests add one more."""

    def __init__(self, path: str):
        self.path = Path(path)
        git_out(self.path, "init", "-q", "-b", "main")
        for key, value in [
            ("user.email", "test@example.com"),
            ("user.name", "test"),
            ("core.autocrlf", "false"),  # keep CR bytes exactly as written
        ]:
            git_out(self.path, "config", key, value)
        self.write("README.md", b"base\n")
        self.commit("base")

    def write(self, rel: str, data: bytes) -> None:
        target = self.path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def commit(self, message: str) -> None:
        git_out(self.path, "add", "-A")
        git_out(self.path, "commit", "-qm", message)

    def scan(self) -> tuple[int, list[tuple[str, str]]]:
        """Scan HEAD~1..HEAD through the CLI: exit code and (path, label) pairs."""
        code, out = self.run_cli("HEAD~1")
        return code, FINDING_RE.findall(out)

    def run_cli(self, base: str) -> tuple[int, str]:
        code, out, _err = run_main(["--base", base, "--root", str(self.path)])
        return code, out

    def head(self) -> str:
        return git_out(self.path, "rev-parse", "HEAD")


class GitDiffTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = ScratchRepo(tmp.name)

    def test_runner_color_config_does_not_hide_the_diff(self):
        # color.ui=always put escape codes before every line of the diff, so
        # the parser recognised no header and scanned nothing.
        self.repo.write("s.txt", f"host {IP}\n".encode())
        self.repo.commit("add")
        git_out(self.repo.path, "config", "color.ui", "always")
        code, found = self.repo.scan()
        self.assertEqual(code, 1)
        self.assertEqual(found, [("s.txt", "private/link-local IP")])

    def test_line_break_lookalikes_do_not_hide_a_line(self):
        # Git ends a line at LF only. Decoding with universal newlines, then
        # splitlines(), broke the added line early at a CR, a form feed or a
        # U+2028, and the host after the break went unscanned.
        files = {
            "cr_only.txt": f"clean\rhost {IP}\r",
            "crlf.txt": f"clean\r\nhost {IP}\r\n",
            "form_feed.txt": f"clean\fhost {IP}\n",
            "line_separator.txt": f"clean host {IP}\n",
        }
        for name, text in files.items():
            self.repo.write(name, text.encode("utf-8"))
        self.repo.commit("add")
        code, found = self.repo.scan()
        self.assertEqual(code, 1)
        self.assertEqual(sorted(found), [(n, "private/link-local IP") for n in files])

    def test_secret_file_under_an_unusual_directory_name_is_flagged(self):
        # Quoted "caf\303\251/.env" and tab-suffixed "my dir/.env" headers
        # used to hide both files from the filename check.
        for name in ["café/.env", "my dir/.env"]:
            self.repo.write(name, b"K=v\n")
        self.repo.commit("add")
        code, found = self.repo.scan()
        self.assertEqual(code, 1)
        self.assertEqual(
            sorted(found),
            [("café/.env", "dotenv file"), ("my dir/.env", "dotenv file")],
        )

    def test_secret_file_that_adds_no_diff_line_is_flagged_by_name(self):
        # A binary file, an empty file and a pure rename show no added line,
        # so their names never reached the filename check.
        self.repo.write("config.txt", b"K=v\n")
        self.repo.commit("a tracked file")
        self.repo.write("client.p12", b"0\x82\x0a\x00\x02\x01\x03")
        self.repo.write("empty/.env", b"")
        git_out(self.repo.path, "mv", "config.txt", ".env.production")
        self.repo.commit("add")
        code, found = self.repo.scan()
        self.assertEqual(code, 1)
        self.assertEqual(
            sorted(found),
            [
                (".env.production", "dotenv file"),
                ("client.p12", "key/cert file"),
                ("empty/.env", "dotenv file"),
            ],
        )

    def test_text_that_git_would_call_binary_is_scanned(self):
        # A NUL byte, or a `-diff` attribute the change adds itself, made git
        # print "Binary files differ" in place of the lines.
        self.repo.write("notes.txt", b"x\x00\nhost " + IP.encode() + b"\n")
        self.repo.write(".gitattributes", b"*.log -diff\n")
        self.repo.write("app.log", f"host {IP}\n".encode())
        self.repo.commit("add")
        code, found = self.repo.scan()
        self.assertEqual(code, 1)
        self.assertEqual(
            sorted(found),
            [
                ("app.log", "private/link-local IP"),
                ("notes.txt", "private/link-local IP"),
            ],
        )

    def test_runner_diff_filters_cannot_rewrite_the_diff(self):
        # A textconv filter or a diff.external command in the runner's git
        # config replaced git's own output. `true` prints nothing at all.
        self.repo.write(".gitattributes", b"*.cfg diff=conv\n")
        self.repo.write("a.cfg", f"host {IP}\n".encode())
        self.repo.commit("add")
        for key in ["diff.conv.textconv", "diff.external"]:
            with self.subTest(config=key):
                git_out(self.repo.path, "config", key, "true")
                code, found = self.repo.scan()
                git_out(self.repo.path, "config", "--unset", key)
                self.assertEqual(code, 1)
                self.assertEqual(found, [("a.cfg", "private/link-local IP")])

    def test_binary_media_is_checked_by_name_not_content(self):
        # --text prints any binary as lines. Real fonts, images, archives and
        # media carry email- and path-shaped byte runs, so their content is
        # skipped when the file starts the way its format does. Other
        # binaries are still read, and a secret name counts.
        payload = b" host " + IP.encode() + b" \x00\xff\n"
        for name, magic in [
            ("logo.png", b"\x89PNG\r\n\x1a\n"),
            ("Font.TTF", b"\x00\x01\x00\x00"),
            ("bundle.tar.gz", b"\x1f\x8b\x08\x00"),
            ("demo.webm", b"\x1a\x45\xdf\xa3"),
            ("backup/.env.zip", b"PK\x03\x04"),
            ("blob.bin", b"\x00\x01\x00\x00"),
        ]:
            self.repo.write(name, magic + payload)
        self.repo.commit("add")
        code, found = self.repo.scan()
        self.assertEqual(code, 1)
        self.assertEqual(
            sorted(found),
            [("backup/.env.zip", "dotenv file"), ("blob.bin", "private/link-local IP")],
        )

    def test_text_with_a_media_name_is_scanned(self):
        # The name alone used to skip the content. A text file called
        # notes.png is still text, and an uncompressed tar holds its member
        # files byte for byte.
        self.repo.write("notes.png", f"host {IP}\n".encode())
        member = f"host {IP}\n".encode()
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as tar:
            info = tarfile.TarInfo("cfg/notes.txt")
            info.size = len(member)
            tar.addfile(info, io.BytesIO(member))
        self.repo.write("backup.tar", archive.getvalue())
        self.repo.commit("add")
        code, found = self.repo.scan()
        self.assertEqual(code, 1)
        self.assertEqual(
            sorted(found),
            [
                ("backup.tar", "private/link-local IP"),
                ("notes.png", "private/link-local IP"),
            ],
        )

    def test_each_commit_is_checked_for_media_as_that_commit_has_it(self):
        # The net diff sees the real PNG the last commit left. The first
        # commit's own notes.png was text, and that commit stays in history.
        self.repo.write("notes.png", f"host {IP}\n".encode())
        self.repo.commit("text named like an image")
        leaking_commit = self.repo.head()
        self.repo.write("notes.png", b"\x89PNG\r\n\x1a\n host " + IP.encode() + b"\n")
        self.repo.commit("a real image")
        code, out = self.repo.run_cli("HEAD~2")
        self.assertEqual(code, 1)
        self.assertEqual(
            COMMIT_FINDING_RE.findall(out),
            [("notes.png", "private/link-local IP", leaking_commit[:12])],
        )
        self.assertEqual(len(FINDING_RE.findall(out)), 1)

    def test_utf16_text_is_scanned(self):
        # PowerShell 5's `>` writes UTF-16 with a BOM. --text prints its lines,
        # but with a NUL after every ASCII character no pattern matched.
        text = (
            "Ethernet adapter:\r\n"
            f"   IPv4 Address. . : {IP}\r\n"
            "   Owner: real.person@gm" + "ail.com\r\n"
        )
        self.repo.write("net.txt", text.encode("utf-16"))
        self.repo.commit("add")
        code, found = self.repo.scan()
        self.assertEqual(code, 1)
        self.assertEqual(
            sorted(found),
            [("net.txt", "email address"), ("net.txt", "private/link-local IP")],
        )

    def test_file_whose_line_looks_like_a_header_is_scanned(self):
        self.repo.write("pp.txt", f"++ /dev/null\nhost {IP}\n".encode())
        self.repo.commit("add")
        code, found = self.repo.scan()
        self.assertEqual(code, 1)
        self.assertEqual(found, [("pp.txt", "private/link-local IP")])


# ---------------------------------------------------------------------------
# Each commit, not just the net diff
# ---------------------------------------------------------------------------


class PullRequestHistoryTests(unittest.TestCase):
    """A pull request whose first commit adds a host and whose second removes it.

    The net diff shows only the clean result, but the first commit stays in
    the branch's history, public once pushed. Main has moved on five commits
    since the branch point, and GitHub's test merge M is built on its tip.
    """

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._tmp.cleanup)
        cls.tmp = Path(cls._tmp.name).resolve()
        (cls.tmp / "upstream").mkdir()
        up = ScratchRepo(str(cls.tmp / "upstream"))
        for i in range(3):
            up.write(f"base{i}.txt", b"base\n")
            up.commit(f"B{i}")
        git_out(up.path, "checkout", "-q", "-b", "feature")
        up.write("s.txt", f"host {IP}\n".encode())
        up.commit("C1: add a host")
        cls.leaking_commit = up.head()
        up.write("s.txt", b"clean\n")
        up.commit("C2: remove it")
        cls.pr_head = up.head()
        git_out(up.path, "checkout", "-q", "main")
        for i in range(5):
            up.write(f"main{i}.txt", b"main\n")
            up.commit(f"X{i}")
        git_out(up.path, "checkout", "-q", "--detach", "main")
        git_out(up.path, "merge", "-q", "--no-ff", "-m", "M", cls.pr_head)
        cls.merge = up.head()
        git_out(up.path, "update-ref", "refs/pull/1/merge", cls.merge)
        git_out(up.path, "checkout", "-q", "main")
        cls.url = up.path.as_uri()

    def checkout(self, depth: int | None = None) -> str:
        """Check out M, then fetch main in full as the action does."""
        runner = checkout_merge(self.tmp, self.url, self.merge, depth)
        git_out(runner, "fetch", "-q", "--no-tags", "origin", "main")
        return runner

    def scan(self, runner: str) -> tuple[int, str]:
        argv = ["--base", "origin/main", "--root", runner, "--pr-head", self.pr_head]
        code, out, err = run_main(argv)
        self.assertNotIn(IP, out + err)  # the masking guarantee holds here too
        return code, out

    def assert_flagged_at_the_leaking_commit(self, code: int, out: str) -> None:
        self.assertEqual(code, 1)
        self.assertEqual(
            COMMIT_FINDING_RE.findall(out),
            [("s.txt", "private/link-local IP", self.leaking_commit[:12])],
        )
        self.assertEqual(len(FINDING_RE.findall(out)), 1)

    def test_line_a_later_commit_removed_is_flagged_at_its_commit(self):
        self.assert_flagged_at_the_leaking_commit(*self.scan(self.checkout()))

    def test_shallow_clone_fetches_the_commits_it_hides(self):
        # Depth 1 is actions/checkout's default. A fetch limited by depth
        # would cut main's history off at M's first parent, where main's own
        # commits would enter the range, so the history is fetched in full.
        runner = self.checkout(depth=1)
        self.assert_flagged_at_the_leaking_commit(*self.scan(runner))
        self.assertEqual(
            git_out(runner, "rev-parse", "--is-shallow-repository"), "false"
        )

    def test_commits_that_stay_hidden_are_an_error(self):
        runner = self.checkout(depth=1)
        # M's first parent is in view, the pull request's first commit is
        # not, and origin is gone, so nothing can bring that commit back.
        git_out(runner, "fetch", "-q", "--no-tags", "--deepen=1", "origin", self.merge)
        git_out(runner, "remote", "set-url", "origin", (self.tmp / "gone").as_uri())
        code, out = self.scan(runner)
        self.assertEqual(code, 2)
        self.assertIn("shallow clone's boundary", out)
        self.assertIn("Fetching their history failed", out)
        self.assertNotIn("clean", out)


class CommitHistoryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = ScratchRepo(tmp.name)

    def test_value_still_in_the_change_is_reported_once(self):
        self.repo.write("s.txt", f"host {IP}\n".encode())
        self.repo.commit("add")
        self.repo.write("t.txt", b"clean\n")
        self.repo.commit("more")
        code, out = self.repo.run_cli("HEAD~2")
        self.assertEqual(code, 1)
        self.assertEqual(FINDING_RE.findall(out), [("s.txt", "private/link-local IP")])
        self.assertEqual(COMMIT_FINDING_RE.findall(out), [])

    def test_secret_file_added_then_deleted_is_flagged_by_name(self):
        self.repo.write("keys/.env.local", b"")
        self.repo.commit("add an empty secret file")
        added = self.repo.head()
        git_out(self.repo.path, "rm", "-q", "keys/.env.local")
        self.repo.commit("delete it")
        code, out = self.repo.run_cli("HEAD~2")
        self.assertEqual(code, 1)
        self.assertEqual(
            COMMIT_FINDING_RE.findall(out),
            [("keys/.env.local", "dotenv file", added[:12])],
        )

    def test_merge_commit_that_adds_a_line_no_parent_had_is_flagged(self):
        # The pull request merges main in and slips a host into that merge,
        # then deletes it. main's own host came from main, so it is not the
        # pull request's to answer for.
        path = self.repo.path
        git_out(path, "checkout", "-q", "-b", "feature")
        self.repo.write("f.txt", b"feature work\n")
        self.repo.commit("F1")
        git_out(path, "checkout", "-q", "main")
        self.repo.write("m.txt", b"host " + b"10.20.30.41" + b"\n")
        self.repo.commit("main moves on")
        git_out(path, "checkout", "-q", "feature")
        git_out(path, "merge", "-q", "--no-ff", "--no-commit", "main")
        self.repo.write("evil.txt", b"host " + b"10.20.30.42" + b"\n")
        self.repo.commit("merge main")
        merge = self.repo.head()
        git_out(path, "rm", "-q", "evil.txt")
        self.repo.commit("F3: delete it")
        code, out = self.repo.run_cli("main")
        self.assertEqual(code, 1)
        self.assertEqual(
            COMMIT_FINDING_RE.findall(out),
            [("evil.txt", "private/link-local IP", merge[:12])],
        )
        self.assertEqual(len(FINDING_RE.findall(out)), 1)

    def test_each_commit_is_read_with_the_diff_hardening(self):
        # The runner's color, textconv and root-commit settings, and a CR-only
        # file, cannot hide a commit's lines any more than the net diff's.
        for key, value in [
            ("color.ui", "always"),
            ("diff.conv.textconv", "true"),
            ("log.showRoot", "false"),
        ]:
            git_out(self.repo.path, "config", key, value)
        self.repo.write(".gitattributes", b"*.cfg diff=conv\n")
        self.repo.write("a.cfg", f"host {IP}\n".encode())
        self.repo.write("m.txt", f"clean\rhost {IP}\r".encode())
        self.repo.commit("add")
        added = self.repo.head()
        self.repo.write("a.cfg", b"clean\n")
        self.repo.write("m.txt", b"clean\n")
        self.repo.commit("clean up")
        code, out = self.repo.run_cli("HEAD~2")
        self.assertEqual(code, 1)
        self.assertEqual(
            sorted(COMMIT_FINDING_RE.findall(out)),
            [
                ("a.cfg", "private/link-local IP", added[:12]),
                ("m.txt", "private/link-local IP", added[:12]),
            ],
        )


class ActionDefinitionTests(unittest.TestCase):
    """These tests never run action.yml's shell step, so guard its key lines."""

    @classmethod
    def setUpClass(cls):
        text = (THIS_DIR / "action.yml").read_text(encoding="utf-8")
        cls.code = [ln for ln in text.splitlines() if not ln.strip().startswith("#")]

    def test_the_base_is_never_fetched_shallow(self):
        # A --depth fetch into the full clone is what grafted a moved base.
        # MovedBaseTests reproduces it.
        self.assertEqual([ln for ln in self.code if "--depth" in ln], [])

    def test_a_commit_sha_base_is_not_read_as_a_branch(self):
        # On a push the base is github.event.before, a SHA, and the step used
        # to pass origin/<sha>, which names nothing, so the scan exited 2.
        self.assertTrue(any("[0-9a-f]{40}" in ln for ln in self.code))
        self.assertTrue(any('--base "$base"' in ln for ln in self.code))

    def test_skipping_the_scanner_files_is_opt_in(self):
        text = (THIS_DIR / "action.yml").read_text(encoding="utf-8")
        declared = re.search(r"\n  skip-scanner-files:\n(?:    .*\n)+", text)
        self.assertIsNotNone(declared)
        self.assertIn("default: 'false'", declared.group(0))
        self.assertTrue(any("--skip-scanner-files" in ln for ln in self.code))

    def test_the_pull_request_head_reaches_the_scanner(self):
        self.assertTrue(
            any("github.event.pull_request.head.sha" in ln for ln in self.code)
        )
        self.assertTrue(any("--pr-head" in ln for ln in self.code))


class BaseRefGuardTests(unittest.TestCase):
    def test_a_base_git_could_read_as_an_option_never_reaches_git(self):
        # git reads a value that starts with "-" as an option. A control
        # character could end a log line and start a workflow command.
        for base in ["--upload-pack=touch INJECTED", "-x", "main\n::warning::forged"]:
            with (
                self.subTest(base=base),
                mock.patch.object(rc, "_git", side_effect=AssertionError("git ran")),
            ):
                code, out, _err = run_main([f"--base={base}"])
                self.assertEqual(code, 2)
                self.assertIn("cannot start with '-' or hold a control", out)
                self.assertEqual(
                    [ln[:8] for ln in out.splitlines() if ln.startswith("::")],
                    ["::error:"],
                )

    def test_the_action_refuses_such_a_base_ref_before_it_fetches(self):
        text = (THIS_DIR / "action.yml").read_text(encoding="utf-8")
        code = [ln for ln in text.splitlines() if not ln.strip().startswith("#")]
        guard = next(i for i, ln in enumerate(code) if "-* | *[[:cntrl:]]*)" in ln)
        fetch = next(i for i, ln in enumerate(code) if "git fetch" in ln)
        self.assertLess(guard, fetch)
        self.assertIn("exit 2", code[guard + 2])
        self.assertIn('origin -- "$BASE_REF"', code[fetch])


def action_step_script() -> str:
    """The scan step's run block from action.yml, as a runner would run it."""
    lines = (THIS_DIR / "action.yml").read_text(encoding="utf-8").splitlines()
    name = next(i for i, ln in enumerate(lines) if "Scan for private-content" in ln)
    start = next(i for i in range(name, len(lines)) if lines[i].strip() == "run: |")
    indent = len(lines[start + 1]) - len(lines[start + 1].lstrip())
    body = []
    for line in lines[start + 1 :]:
        if line.strip() and len(line) - len(line.lstrip()) < indent:
            break
        body.append(line[indent:])
    script = "\n".join(body) + "\n"
    script = script.replace("${{ github.action_path }}", THIS_DIR.as_posix())
    if "${{" in script:
        raise AssertionError("an expression other than github.action_path is left")
    return script


# System32's bash.exe is WSL's, which cannot run the Windows git and python.
BASH = shutil.which("bash")
if BASH and os.name == "nt" and "system32" in BASH.lower():
    BASH = None


@unittest.skipUnless(BASH, "needs bash, as a runner has")
class ActionStepTests(unittest.TestCase):
    """Run action.yml's own scan step, the shell text a runner executes."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._tmp.cleanup)
        cls.tmp = Path(cls._tmp.name).resolve()
        # `python` in the step is this interpreter, whatever PATH holds.
        shim = cls.tmp / "bin"
        shim.mkdir()
        python = Path(sys.executable).as_posix()
        (shim / "python").write_text(
            f'#!/bin/sh\nexec "{python}" "$@"\n', encoding="utf-8", newline="\n"
        )
        (shim / "python").chmod(0o755)
        cls.script = cls.tmp / "step.sh"
        cls.script.write_text(action_step_script(), encoding="utf-8", newline="\n")
        (cls.tmp / "upstream").mkdir()
        up = ScratchRepo(str(cls.tmp / "upstream"))
        cls.base = up.head()
        up.write("notes.txt", f"host {IP}\n".encode())
        up.commit("add a host")
        cls.url = up.path.as_uri()

    def clone(self) -> Path:
        runner = Path(tempfile.mkdtemp(dir=self.tmp))
        git_out(self.tmp, "clone", "-q", self.url, str(runner))
        return runner

    def run_step(self, cwd: Path, **env: str) -> tuple[int, str]:
        outputs = Path(tempfile.mkdtemp(dir=self.tmp)) / "github_output"
        step_env = {
            **os.environ,
            "PATH": str(self.tmp / "bin") + os.pathsep + os.environ["PATH"],
            "FAIL_ON": "match",
            "SCAN_MODE": "added-lines",
            "PATTERNS_FILE": "",
            "SKIP_SCANNER_FILES": "false",
            "BASE_REF": "",
            "PR_BASE_REF": "",
            "PR_HEAD_SHA": "",
            "GITHUB_OUTPUT": outputs.as_posix(),
            "RUNNER_TEMP": self.tmp.as_posix(),
            **env,
        }
        result = subprocess.run(
            [BASH, self.script.as_posix()],
            cwd=cwd,
            env=step_env,
            capture_output=True,
            check=False,
        )
        return result.returncode, rc._text(result.stdout + result.stderr)

    def test_a_base_ref_that_looks_like_an_option_runs_no_command(self):
        # Over a file or ssh remote, git fetch ran --upload-pack's command.
        runner = self.clone()
        base_ref = "--upload-pack=touch${IFS}INJECTED;git-upload-pack"
        code, out = self.run_step(runner, BASE_REF=base_ref)
        self.assertEqual(code, 2, out)
        self.assertIn("::error::base-ref cannot start with '-'", out)
        self.assertFalse((runner / "INJECTED").exists())

    def test_a_base_ref_with_a_newline_cannot_forge_a_command(self):
        runner = self.clone()
        code, out = self.run_step(runner, BASE_REF="main\n::warning::forged")
        self.assertEqual(code, 2, out)
        self.assertNotIn("\n::warning::", "\n" + out)

    def test_a_commit_sha_base_ref_is_scanned(self):
        code, out = self.run_step(self.clone(), BASE_REF=self.base)
        self.assertEqual(code, 1, out)
        self.assertEqual(
            FINDING_RE.findall(out), [("notes.txt", "private/link-local IP")]
        )


class SelftestTests(unittest.TestCase):
    def test_selftest_passes_via_direct_call(self):
        self.assertEqual(rc.run_selftest(), 0)

    def test_selftest_passes_via_subprocess(self):
        # One end-to-end smoke test through the real CLI entry point (the
        # #!/usr/bin/env python3 script as a subprocess), not just main().
        result = subprocess.run(
            [sys.executable, str(THIS_DIR / "redaction_check.py"), "--selftest"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("selftest: PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
