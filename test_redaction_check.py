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

    def test_a_byte_that_is_not_utf8_does_not_skip_the_file(self):
        # A strict decode gave up on the whole file at the Latin-1 byte.
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q"], cwd=tmp, check=True)
            text = b"caf\xe9 menu\nhost " + IP.encode() + b"\n"
            (Path(tmp) / "latin1.txt").write_bytes(text)
            subprocess.run(["git", "add", "-A"], cwd=tmp, check=True)
            found = [(f.path, f.line, f.label) for f in rc.scan_all_files(tmp)]
        self.assertEqual(found, [("latin1.txt", 2, "private/link-local IP")])

    def test_media_content_is_skipped_only_for_the_real_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q"], cwd=tmp, check=True)
            payload = b" host " + IP.encode() + b"\n"
            (Path(tmp) / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + payload)
            (Path(tmp) / "notes.png").write_bytes(payload)
            (Path(tmp) / "net.txt").write_bytes(payload.decode().encode("utf-16"))
            subprocess.run(["git", "add", "-A"], cwd=tmp, check=True)
            found = sorted((f.path, f.label) for f in rc.scan_all_files(tmp))
        self.assertEqual(
            found,
            [
                ("net.txt", "private/link-local IP"),
                ("notes.png", "private/link-local IP"),
            ],
        )

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


def checkout_like_actions(
    tmp: Path, url: str, branch: str = "", merge: str = ""
) -> Path:
    """Clone as actions/checkout does with fetch-depth: 0.

    Every branch lands in refs/remotes/origin/ and every tag in refs/tags/.
    A push to branch is checked out with `checkout -B <branch>`, as
    actions/checkout does, which makes a local branch of that name. Without
    a branch, the test-merge commit merge is checked out detached.
    """
    runner = Path(tempfile.mkdtemp(dir=tmp))
    git_out(runner, "init", "-q")
    git_out(runner, "remote", "add", "origin", url)
    refspecs = ["+refs/heads/*:refs/remotes/origin/*", "+refs/tags/*:refs/tags/*"]
    if merge:
        refspecs.append(f"+{merge}:refs/remotes/pull/1/merge")
    git_out(runner, "fetch", "-q", "origin", *refspecs)
    if branch:
        start = f"refs/remotes/origin/{branch}"
        git_out(runner, "checkout", "-q", "--force", "-B", branch, start)
    else:
        git_out(runner, "checkout", "-q", "--detach", "refs/remotes/pull/1/merge")
    return runner


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

    def test_a_rewritten_base_gives_the_allow_file_from_its_tip(self):
        # The widened range starts at the merge base, before the rewrite, so
        # the list comes from the base as it now stands.
        runner = self.checkout()
        frm, to, _how = rc.resolve_diff_range("origin/main", runner, self.pr_head)
        tip = git_out(runner, "rev-parse", "origin/main")
        self.assertEqual(
            rc.allow_source("origin/main", frm, to, runner, self.pr_head),
            (tip, f"at {tip[:12]} (origin/main)"),
        )

    def test_rewritten_base_without_history_to_widen_from_is_an_error(self):
        # At depth 1 the first parent arrives by deepening, as a shallow
        # boundary, so no merge base is visible. The base's own history is
        # complete, which proves the rewrite, so the gate refuses to pass.
        code, out = self.scan(self.checkout(depth=1))
        self.assertEqual(code, 2)
        self.assertIn("was rewritten", out)
        self.assertNotIn("clean", out)


class ShadowedRefTests(unittest.TestCase):
    """A tag or a local branch called origin/main must never stand in for main.

    git reads a short name through a fixed list of places and takes the first
    ref that exists, so refs/tags/origin/main and refs/heads/origin/main both
    win over refs/remotes/origin/main, with only a warning. A pull request
    branched from an older main adds a host in H, and GitHub builds its test
    merge M on main's newer tip T1. With a tag named origin/main at H, the scan
    took H for a rewritten base, widened to the merge base of H and M, which
    is H itself, and left the pull request's own line out.
    """

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._tmp.cleanup)
        cls.tmp = Path(cls._tmp.name).resolve()
        (cls.tmp / "upstream").mkdir()
        up = ScratchRepo(str(cls.tmp / "upstream"))
        cls.base = up.head()
        up.write("later.txt", b"later\n")
        up.commit("T1: main moves on")
        cls.main_tip = up.head()
        git_out(up.path, "checkout", "-q", "-b", "feature", cls.base)
        up.write("more.txt", f"host {IP}\n".encode())
        up.commit("H: add a host")
        cls.pr_head = up.head()
        git_out(up.path, "checkout", "-q", "--detach", cls.main_tip)
        git_out(up.path, "merge", "-q", "--no-ff", "-m", "M", cls.pr_head)
        cls.merge = up.head()
        git_out(up.path, "update-ref", "refs/pull/1/merge", cls.merge)
        git_out(up.path, "checkout", "-q", "main")
        cls.url = up.path.as_uri()

    def merge_checkout(self) -> str:
        return str(checkout_like_actions(self.tmp, self.url, merge=self.merge))

    def head_checkout(self) -> str:
        return str(checkout_like_actions(self.tmp, self.url, branch="feature"))

    def test_a_short_name_a_tag_or_a_local_branch_shadows_is_refused(self):
        for kind, shadow in [("tag", "refs/tags"), ("branch", "refs/heads")]:
            for checkout, pr_head in [
                (self.merge_checkout, self.pr_head),
                (self.head_checkout, None),
            ]:
                with self.subTest(kind=kind, checkout=checkout.__name__):
                    runner = checkout()
                    git_out(runner, kind, "origin/main", self.pr_head)
                    with self.assertRaises(rc.DiffError) as ctx:
                        rc.resolve_diff_range("origin/main", runner, pr_head)
                    message = str(ctx.exception)
                    self.assertIn("origin/main is ambiguous here.", message)
                    self.assertIn(
                        f"It could name {shadow}/origin/main or "
                        "refs/remotes/origin/main, and git would read "
                        f"{shadow}/origin/main.",
                        message,
                    )

    def test_the_full_name_reads_main_past_a_tag_and_a_branch_of_that_name(self):
        runner = self.merge_checkout()
        git_out(runner, "tag", "origin/main", self.pr_head)
        git_out(runner, "branch", "origin/main", self.pr_head)
        base = "refs/remotes/origin/main"
        frm, to, how = rc.resolve_diff_range(base, runner, self.pr_head)
        self.assertEqual((frm, to), (self.main_tip, self.merge))
        self.assertIn("test-merge commit", how)
        argv = ["--base", base, "--root", runner, "--pr-head", self.pr_head]
        code, out, _err = run_main(argv)
        self.assertEqual(code, 1, out)
        self.assertEqual(
            FINDING_RE.findall(out), [("more.txt", "private/link-local IP")]
        )
        # A checkout of the head itself, where the tag made the range empty.
        runner = self.head_checkout()
        git_out(runner, "tag", "origin/main", self.pr_head)
        frm, to, _how = rc.resolve_diff_range(base, runner)
        self.assertEqual((frm, to), (self.base, self.pr_head))

    def test_the_cli_refuses_a_shadowed_base_and_never_passes(self):
        runner = self.merge_checkout()
        git_out(runner, "tag", "origin/main", self.pr_head)
        for fail_on in ["match", "none"]:
            with self.subTest(fail_on=fail_on):
                argv = ["--base", "origin/main", "--root", runner, "--fail-on", fail_on]
                code, out, _err = run_main([*argv, "--pr-head", self.pr_head])
                self.assertEqual(code, 2, out)
                self.assertIn("::error::", out)
                self.assertIn("origin/main is ambiguous here.", out)
                self.assertNotIn("Scanning", out)
                self.assertNotIn("clean", out)

    def test_an_expression_on_a_shadowed_name_is_refused(self):
        runner = self.head_checkout()
        git_out(runner, "branch", "origin/main", self.pr_head)
        with self.assertRaises(rc.DiffError):
            rc.resolve_diff_range("origin/main~0", runner)

    def test_a_missing_full_name_is_not_read_as_a_branch_that_repeats_it(self):
        # git reads refs/remotes/origin/main, when there is no such ref, as a
        # branch of that name, which actions/checkout makes for a push to it.
        runner = self.head_checkout()
        git_out(runner, "update-ref", "-d", "refs/remotes/origin/main")
        git_out(runner, "branch", "refs/remotes/origin/main", self.pr_head)
        with self.assertRaises(rc.DiffError) as ctx:
            rc.resolve_diff_range("refs/remotes/origin/main", runner)
        self.assertIn(
            "would read it as refs/heads/refs/remotes/origin/main", str(ctx.exception)
        )

    def test_an_existing_full_name_is_read_whatever_else_repeats_it(self):
        # git reads a full name as itself first. Refusing it here would let
        # anyone who can push a tag of that name fail every scan.
        runner = self.head_checkout()
        git_out(runner, "tag", "refs/remotes/origin/main", self.pr_head)
        frm, to, _how = rc.resolve_diff_range("refs/remotes/origin/main", runner)
        self.assertEqual((frm, to), (self.base, self.pr_head))

    def test_a_full_sha_is_that_commit_whatever_refs_share_its_name(self):
        runner = self.head_checkout()
        git_out(runner, "tag", self.base, self.pr_head)
        git_out(runner, "branch", self.base, self.pr_head)
        frm, to, _how = rc.resolve_diff_range(self.base, runner)
        self.assertEqual((frm, to), (self.base, self.pr_head))

    def test_git_reads_a_short_name_in_the_order_the_scanner_checks(self):
        # refs_named keeps its own copy of git's list. Pin it to the git that
        # runs it: git's first choice is always the first ref it returns.
        runner = self.head_checkout()
        name = "pin/x"
        refs = [rule.format(name) for rule in rc.REF_RULES[1:5]]
        for ref in refs:
            git_out(runner, "update-ref", ref, self.pr_head)
        first = ["-c", "core.warnAmbiguousRefs=false", "rev-parse"]
        while refs:
            with self.subTest(refs=refs):
                self.assertEqual(rc.refs_named(name, runner), refs)
                picked = git_out(runner, *first, "--symbolic-full-name", name)
                self.assertEqual(picked, refs[0])
            git_out(runner, "update-ref", "-d", refs.pop(0))
        # The last place, which cannot sit beside refs/remotes/pin/x.
        last = rc.REF_RULES[5].format(name)
        git_out(runner, "update-ref", last, self.pr_head)
        self.assertEqual(rc.refs_named(name, runner), [last])
        self.assertEqual(git_out(runner, *first, "--symbolic-full-name", name), last)


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


# ---------------------------------------------------------------------------
# Allow file -- exact values a repository vouches for
# ---------------------------------------------------------------------------

# An mDNS-shaped value that is really a Python module path, the case the allow
# file exists for.
MODULE = "adapters" + ".local"
OTHER_MODULE = "reports" + ".local"
AWS_KEY = "AKIA" + "EXAMPLE000000000"
OTHER_IP = "10.20.30.41"
ALLOW = ".redaction-allow"
MARKED = "  # redaction-ok: a module path, not a host"
FIXTURE_OK = "  # redaction-ok: a test fixture"


def allow_list(*entries: str) -> rc.Allowlist:
    return rc.Allowlist(frozenset(entries), ALLOW, found=True)


def one_file_diff(path: str, *lines: str) -> str:
    """A diff that adds path with these lines."""
    return (
        f"diff --git a/{path} b/{path}\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        f"+++ b/{path}\n"
        f"@@ -0,0 +1,{len(lines)} @@\n" + "".join(f"+{ln}\n" for ln in lines)
    )


class AllowFileParsingTests(unittest.TestCase):
    def parse(self, text: str) -> tuple[frozenset[str], list[str]]:
        return rc.parse_allowlist(text, "Allow file .redaction-allow at HEAD")

    def test_comments_and_blank_lines_are_skipped(self):
        text = f"# module paths\n\n   \n{MODULE}{MARKED}\n\t# indented\nkey#part\n"
        self.assertEqual(self.parse(text), ({MODULE, "key#part"}, []))

    def test_short_and_whitespace_entries_are_ignored_with_a_warning(self):
        key_header = "-----BEGIN " + "RSA PRIVATE KEY-----"
        entries, warnings = self.parse(f"abc\n{MODULE}\n{key_header}\n  x  \n")
        self.assertEqual(entries, {MODULE})
        where = "Allow file .redaction-allow at HEAD, line"
        self.assertEqual(
            warnings,
            [
                f"{where} 1: entry ignored, shorter than 4 characters.",
                f"{where} 3: entry ignored, it holds whitespace.",
                f"{where} 4: entry ignored, shorter than 4 characters.",
            ],
        )
        # The file may hold a real value, so a warning never repeats a line.
        self.assertNotIn("abc", " ".join(warnings))
        self.assertNotIn("PRIVATE", " ".join(warnings))

    def test_the_list_is_capped(self):
        cap = rc.ALLOW_MAX_ENTRIES
        entries, warnings = self.parse(
            "".join(f"value-{i:03d}\n" for i in range(cap + 5))
        )
        self.assertEqual(len(entries), cap)
        self.assertIn("value-000", entries)
        self.assertNotIn(f"value-{cap:03d}", entries)
        self.assertEqual(len(warnings), 1)
        self.assertIn(f"5 entries from line {cap + 1} on ignored", warnings[0])

    def test_a_utf16_allow_file_is_read(self):
        # What PowerShell 5's `>` writes.
        data = f"{MODULE}\r\n".encode("utf-16")
        self.assertEqual(self.parse(rc.allow_text(data)), ({MODULE}, []))

    def test_a_utf16_be_or_utf8_bom_is_read(self):
        for data in (
            b"\xfe\xff" + f"{MODULE}\n".encode("utf-16-be"),
            b"\xef\xbb\xbf" + f"{MODULE}\n".encode(),
        ):
            with self.subTest(bom=data[:3]):
                self.assertEqual(self.parse(rc.allow_text(data)), ({MODULE}, []))

    def test_an_entry_is_trimmed_at_both_ends(self):
        text = f"  {MODULE}\n\t{OTHER_MODULE}\t# why\n"
        self.assertEqual(self.parse(text), ({MODULE, OTHER_MODULE}, []))

    def test_a_four_character_entry_is_kept(self):
        self.assertEqual(self.parse("a.io\n"), ({"a.io"}, []))

    def test_the_cap_counts_unique_valid_entries_only(self):
        # Comments, blanks, ignored lines and repeats take no place on it.
        lines = ["# c", "", "abc"] * 50 + ["value-000"] * 50
        lines += [f"value-{i:03d}" for i in range(201)]
        entries, warnings = self.parse("\n".join(lines))
        self.assertEqual(len(entries), 200)
        self.assertIn("value-199", entries)
        self.assertNotIn("value-200", entries)
        self.assertEqual(sum("past the first" in w for w in warnings), 1)

    def test_an_entry_holding_a_byte_that_is_not_text_is_ignored(self):
        # Every such byte decodes to U+FFFD, in the scanned lines too, so the
        # entry would cover values with any other such byte in its place.
        entries, warnings = self.parse(rc.allow_text(b"tok=ab\xff\n" + b"a.io\n"))
        self.assertEqual(entries, {"a.io"})
        self.assertEqual(len(warnings), 1)
        self.assertIn("line 1: entry ignored, it holds U+FFFD", warnings[0])


class AllowFileMatchingTests(unittest.TestCase):
    def scan(self, allow: rc.Allowlist, line: str) -> list[tuple[str, bool]]:
        found = rc.scan_added_lines(one_file_diff("app.py", line), allow=allow)
        return [(f.label, f.allowed) for f in found]

    def test_an_exact_match_is_suppressed(self):
        self.assertEqual(
            self.scan(allow_list(MODULE), f"from pkg.{MODULE} import load"),
            [("mDNS/.local hostname", True)],
        )

    def test_another_finding_on_the_same_line_is_still_reported(self):
        self.assertEqual(
            self.scan(allow_list(MODULE), f"{MODULE} runs on {IP}"),
            [("private/link-local IP", False), ("mDNS/.local hostname", True)],
        )

    def test_a_substring_or_superstring_is_still_reported(self):
        for text, entry in [
            ("my" + MODULE, MODULE),  # the match holds the entry
            (MODULE, "my" + MODULE),  # the match sits inside the entry
            (MODULE, MODULE.upper()),  # case counts
            (IP, IP[:-1]),
        ]:
            with self.subTest(text=text, entry=entry):
                found = self.scan(allow_list(entry), f"see {text} here")
                self.assertEqual([allowed for _label, allowed in found], [False])

    def test_a_secret_filename_is_never_allowed(self):
        diff = one_file_diff(".env", "K=value")
        found = rc.scan_added_lines(diff, allow=allow_list(".env", "K=value"))
        self.assertEqual(
            [(f.label, f.allowed) for f in found], [("dotenv file", False)]
        )

    def test_an_entry_with_a_byte_that_is_not_text_covers_nothing(self):
        entries, _warnings = rc.parse_allowlist(rc.allow_text(b"tok=ab\xff\n"), "x")
        allow = rc.Allowlist(entries, ALLOW, found=True)
        custom = [("custom", re.compile(r"tok=\S+"))]
        diff = one_file_diff("c.txt", rc._text(b"tok=ab\x80"))
        found = rc.scan_added_lines(diff, custom, allow=allow)
        self.assertEqual([f.allowed for f in found], [False])

    def test_an_allowed_ip_hides_an_ip_that_overlaps_it(self):
        # A limit the README states: a pattern never reports two matches that
        # overlap. The second address here starts inside the first and is
        # never found, so allowing the first lets the whole run through.
        self.assertEqual(
            self.scan(allow_list("10.0.0.10"), "route 10.0.0.10.0.0.2"),
            [("private/link-local IP", True)],
        )


class AllowFileModeTests(unittest.TestCase):
    """Where each mode reads the list from. Never from the change it scans."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = ScratchRepo(tmp.name)

    def scan(self, *argv: str) -> tuple[int, str]:
        root = ["--root", str(self.repo.path), "--allow-file", ALLOW]
        code, out, err = run_main([*argv, *root])
        for value in [MODULE, OTHER_MODULE, AWS_KEY]:
            self.assertNotIn(value, out + err)  # the masking guarantee
        return code, out

    def test_pr_mode_reads_the_base_so_an_entry_the_head_adds_allows_nothing(self):
        self.repo.write(ALLOW, f"{MODULE}\n".encode())
        self.repo.commit("allow the module path on main")
        base_tip = self.repo.head()
        git_out(self.repo.path, "checkout", "-q", "-b", "feature")
        self.repo.write(ALLOW, f"{MODULE}\n{OTHER_MODULE}{MARKED}\n".encode())
        self.repo.write(
            "app.py", f"import pkg.{MODULE}\nimport pkg.{OTHER_MODULE}\n".encode()
        )
        self.repo.commit("use both, and allow the second as well")
        pr_head = self.repo.head()
        # GitHub's test merge: first parent main's tip, second the head.
        git_out(self.repo.path, "checkout", "-q", "--detach", base_tip)
        git_out(self.repo.path, "merge", "-q", "--no-ff", "-m", "M", pr_head)
        code, out = self.scan("--base", "main", "--pr-head", pr_head)
        self.assertEqual(code, 1)
        self.assertIn("test-merge commit", out)
        self.assertEqual(FINDING_RE.findall(out), [("app.py", "mDNS/.local hostname")])
        self.assertIn("::error file=app.py,line=2::", out)
        self.assertIn(
            f"at {base_tip[:12]} (the commit the test merge was built on): 1 entry, 1 ",
            out,
        )

    def test_each_commit_gets_the_base_list_not_its_parent_s(self):
        self.repo.write(ALLOW, f"{MODULE}{MARKED}\n".encode())
        self.repo.commit("allow the module path")
        self.repo.write("app.py", f"import pkg.{MODULE}\n".encode())
        self.repo.commit("use it")
        used = self.repo.head()
        self.repo.write("app.py", b"import pkg.other\n")
        self.repo.commit("stop using it")
        code, out = self.scan("--base", "HEAD~3")
        self.assertEqual(code, 1)
        self.assertEqual(
            COMMIT_FINDING_RE.findall(out),
            [("app.py", "mDNS/.local hostname", used[:12])],
        )
        self.assertIn(": none at ", out)

    def test_all_files_reads_the_list_as_head_has_it(self):
        self.repo.write(ALLOW, f"{MODULE}{MARKED}\n".encode())
        self.repo.write(
            "app.py", f"import pkg.{MODULE}\nimport pkg.{OTHER_MODULE}\n".encode()
        )
        self.repo.commit("add")
        # An entry that is not committed is not on the list.
        self.repo.write(ALLOW, f"{MODULE}{MARKED}\n{OTHER_MODULE}{MARKED}\n".encode())
        code, out = self.scan("--mode", "all-files")
        self.assertEqual(code, 1)
        self.assertEqual(FINDING_RE.findall(out), [("app.py", "mDNS/.local hostname")])
        self.assertIn("::error file=app.py,line=2::", out)
        self.assertIn("at HEAD: 1 entry, 1 match(es) suppressed", out)

    def test_a_secret_put_in_the_allow_file_is_reported(self):
        self.repo.write(ALLOW, f"{AWS_KEY}\n".encode())
        self.repo.write("deploy.sh", f"export KEY={AWS_KEY}\n".encode())
        self.repo.commit("vouch for a real key")
        label = "AWS access key ID"
        # The base had no entry, so both lines are reported.
        code, out = self.scan("--base", "HEAD~1")
        self.assertEqual(code, 1)
        self.assertEqual(
            sorted(FINDING_RE.findall(out)), [(ALLOW, label), ("deploy.sh", label)]
        )
        # HEAD has the entry, but the list never covers the allow file itself.
        code, out = self.scan("--mode", "all-files")
        self.assertEqual((code, FINDING_RE.findall(out)), (1, [(ALLOW, label)]))
        # Nor does it when a caller hands over the branch's own copy.
        diff = rc.get_diff_via_git("HEAD~1", str(self.repo.path))
        argv = ["--allow-file", str(self.repo.path / ALLOW)]
        code, out, err = run_main(argv, stdin_text=diff)
        self.assertEqual((code, FINDING_RE.findall(out)), (1, [(ALLOW, label)]))
        self.assertNotIn(AWS_KEY, out + err)

    def test_a_diff_on_stdin_reads_the_file_named_and_writes_the_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            allow = Path(tmp) / ALLOW
            allow.write_text(f"{MODULE}\n", encoding="utf-8")
            summary = Path(tmp) / "summary.md"
            argv = ["--allow-file", str(allow), "--summary-file", str(summary)]
            diff = one_file_diff("app.py", f"import pkg.{MODULE}", f"host {IP}")
            code, out, _err = run_main(argv, stdin_text=diff)
            text = summary.read_text(encoding="utf-8")
        self.assertEqual(code, 1)
        self.assertEqual(FINDING_RE.findall(out), [("app.py", "private/link-local IP")])
        self.assertIn("on disk: 1 entry, 1 match(es) suppressed.", out)
        self.assertIn("- Findings: 1\n", text)
        self.assertIn("on disk: 1 entry, 1 match(es) suppressed.", text)
        self.assertNotIn(MODULE, out + text)

    def fork_then_move_main(self, at_fork: str, later: str) -> str:
        """Give main's allow file at_fork, fork feature, which uses MODULE, then
        give main's allow file later. Returns feature's head, checked out."""
        self.repo.write(ALLOW, at_fork.encode())
        self.repo.commit("main's list when feature forks")
        git_out(self.repo.path, "checkout", "-q", "-b", "feature")
        self.repo.write("app.py", f"import pkg.{MODULE}\n".encode())
        self.repo.commit("use it")
        head = self.repo.head()
        git_out(self.repo.path, "checkout", "-q", "main")
        self.repo.write(ALLOW, later.encode())
        self.repo.commit("main's list moves on")
        git_out(self.repo.path, "checkout", "-q", "feature")
        return head

    def test_a_checkout_of_the_head_reads_the_base_as_it_is_now(self):
        # The head checked out, as with pull_request_target or ref: head.sha,
        # and --base alone, as for a base-ref set by hand. The list used to
        # come from the merge base, where feature forked, so an entry main
        # had removed since still counted.
        head = self.fork_then_move_main(f"{MODULE}{MARKED}\n", "# revoked\n")
        main = git_out(self.repo.path, "rev-parse", "main")
        for pr_head in (["--pr-head", head], []):
            with self.subTest(pr_head=pr_head):
                code, out = self.scan("--base", "main", *pr_head)
                self.assertEqual(code, 1, out)
                self.assertIn(f"at {main[:12]} (main): 0 entries, 0 ", out)

    def test_an_entry_the_base_gains_after_the_fork_counts(self):
        head = self.fork_then_move_main("# none yet\n", f"{MODULE}{MARKED}\n")
        code, out = self.scan("--base", "main", "--pr-head", head)
        self.assertEqual(code, 0, out)
        self.assertIn("(main): 1 entry, 1 match(es) suppressed.", out)

    def test_the_test_merge_reads_the_commit_it_was_built_on(self):
        # A base that moves on while the check is queued doesn't change it.
        head = self.fork_then_move_main("# none yet\n", f"{MODULE}{MARKED}\n")
        built_on = git_out(self.repo.path, "rev-parse", "main~1")
        git_out(self.repo.path, "checkout", "-q", "--detach", built_on)
        git_out(self.repo.path, "merge", "-q", "--no-ff", "-m", "M", head)
        code, out = self.scan("--base", "main", "--pr-head", head)
        self.assertEqual(code, 1, out)
        where = f"at {built_on[:12]} (the commit the test merge was built on)"
        self.assertIn(f"{where}: 0 entries, 0 match(es) suppressed.", out)

    def test_a_push_range_reads_its_base_unless_allow_ref_names_another(self):
        # Pushed to main, before is main's own history. Pushed to another
        # branch, before is the pusher's last push, so the action names the
        # default branch in --allow-ref.
        self.repo.write(ALLOW, f"{MODULE}{MARKED}\n".encode())
        self.repo.commit("main vouches for one module path")
        git_out(self.repo.path, "checkout", "-q", "-b", "feature")
        self.repo.write(ALLOW, f"{MODULE}{MARKED}\n{OTHER_MODULE}{MARKED}\n".encode())
        self.repo.commit("push 1 vouches for another")
        before = self.repo.head()
        self.repo.write(
            "app.py", f"import pkg.{MODULE}\nimport pkg.{OTHER_MODULE}\n".encode()
        )
        self.repo.commit("push 2 uses both")
        code, out = self.scan("--base", before)
        self.assertEqual(code, 0, out)
        self.assertIn(f"at {before[:12]}: 2 entries, 2 match(es) suppressed.", out)
        code, out = self.scan("--base", before, "--allow-ref", "main")
        self.assertEqual(code, 1, out)
        self.assertEqual(FINDING_RE.findall(out), [("app.py", "mDNS/.local hostname")])
        self.assertIn("::error file=app.py,line=2::", out)
        main = git_out(self.repo.path, "rev-parse", "main")
        self.assertIn(f"at {main[:12]} (main): 1 entry, 1 match(es) suppressed.", out)

    def test_a_ref_that_names_no_commit_means_no_list(self):
        self.repo.write(ALLOW, f"{MODULE}{MARKED}\n".encode())
        self.repo.commit("vouch")
        base = self.repo.head()
        self.repo.write("app.py", f"import pkg.{MODULE}\n".encode())
        self.repo.commit("use it")
        # The base and HEAD both vouch for it. Neither stands in.
        code, out = self.scan("--base", base, "--allow-ref", "origin/main")
        self.assertEqual(code, 1, out)
        missing = "from origin/main, which names no commit in this clone"
        self.assertIn(
            f"::notice::No allow file was read, since it comes {missing}.", out
        )
        self.assertIn(f": none {missing}, so nothing was suppressed.", out)

    def test_an_allow_ref_git_could_read_two_ways_fails_the_scan(self):
        # git reads a short origin/main as a tag or a local branch of that
        # name before the remote-tracking branch. The scan refuses the name
        # rather than read whichever list git took, or read none.
        self.repo.write(ALLOW, b"# main vouches for nothing\n")
        self.repo.commit("main's list")
        main = self.repo.head()
        git_out(self.repo.path, "update-ref", "refs/remotes/origin/main", main)
        git_out(self.repo.path, "checkout", "-q", "-b", "feature")
        self.repo.write(ALLOW, f"{MODULE}{MARKED}\n".encode())
        self.repo.commit("push 1 vouches on the branch")
        before = self.repo.head()
        self.repo.write("app.py", f"import pkg.{MODULE}\n".encode())
        self.repo.commit("push 2 uses it")
        for kind, delete in [("tag", "-d"), ("branch", "-D")]:
            with self.subTest(kind=kind):
                git_out(self.repo.path, kind, "origin/main", "HEAD")
                code, out = self.scan("--base", before, "--allow-ref", "origin/main")
                self.assertEqual(code, 2, out)
                self.assertIn(
                    "::error::Redaction gate cannot tell which allow file to "
                    "read. origin/main is ambiguous here.",
                    out,
                )
                self.assertNotIn("::notice::", out)
                self.assertNotIn("Allow file", out)
                full = "refs/remotes/origin/main"
                code, out = self.scan("--base", before, "--allow-ref", full)
                self.assertEqual(code, 1, out)
                self.assertIn(f"at {main[:12]} ({full}): 0 entries, 0 ", out)
                git_out(self.repo.path, kind, delete, "origin/main")

    def test_a_vouched_value_left_in_the_allow_file_s_history_is_reported(self):
        # The net diff lets the value through in app.py. The commit that
        # listed it a second time, bare, is still in history, and a match an
        # allow file covers never stands in for one it doesn't.
        self.repo.write(ALLOW, f"{MODULE}{MARKED}\n".encode())
        self.repo.commit("vouch")
        base = self.repo.head()
        self.repo.write(ALLOW, f"{MODULE}{MARKED}\n{MODULE}\n".encode())
        self.repo.write("app.py", f"import pkg.{MODULE}\n".encode())
        self.repo.commit("use it, and list it again without a reason")
        listed = self.repo.head()
        self.repo.write(ALLOW, f"{MODULE}{MARKED}\n".encode())
        self.repo.commit("drop the bare line")
        code, out = self.scan("--base", base)
        self.assertEqual(code, 1, out)
        self.assertEqual(
            COMMIT_FINDING_RE.findall(out),
            [(ALLOW, "mDNS/.local hostname", listed[:12])],
        )

    def vouch_for_a_real_key(self) -> None:
        self.repo.write(ALLOW, f"{AWS_KEY}\n".encode())
        self.repo.write("deploy.sh", f"KEY={AWS_KEY}\n".encode())
        self.repo.commit("vouch for a real key")

    def test_all_files_scans_the_committed_list_not_a_local_edit(self):
        # The list comes from HEAD, so its own lines are scanned from there.
        self.vouch_for_a_real_key()
        self.repo.write(ALLOW, b"# edited, not committed\n")
        code, out = self.scan("--mode", "all-files")
        self.assertEqual(FINDING_RE.findall(out), [(ALLOW, "AWS access key ID")])
        self.assertEqual(code, 1)

    def test_all_files_scans_the_committed_list_whatever_its_size(self):
        pad = ("# " + "x" * 98 + "\n") * 21_000  # past MAX_FILE_BYTES
        self.assertGreater(len(pad), rc.MAX_FILE_BYTES)
        self.repo.write(ALLOW, f"{AWS_KEY}\n{pad}".encode())
        self.repo.write("deploy.sh", f"KEY={AWS_KEY}\n".encode())
        self.repo.commit("vouch for a real key, padded")
        code, out = self.scan("--mode", "all-files")
        self.assertEqual(FINDING_RE.findall(out), [(ALLOW, "AWS access key ID")])
        self.assertEqual(code, 1)

    def test_all_files_scans_the_committed_list_once_it_is_gone_from_disk(self):
        self.vouch_for_a_real_key()
        git_out(self.repo.path, "rm", "-q", ALLOW)
        code, out = self.scan("--mode", "all-files")
        self.assertEqual(FINDING_RE.findall(out), [(ALLOW, "AWS access key ID")])
        self.assertEqual(code, 1)

    def test_all_files_scans_the_allow_file_once_under_any_path_form(self):
        # git reads HEAD:./.redaction-allow too. The walk must still know
        # the working-tree copy is the same file, and leave it out.
        self.vouch_for_a_real_key()
        root = str(self.repo.path)
        argv = ["--mode", "all-files", "--root", root, "--allow-file", "./" + ALLOW]
        code, out, _err = run_main(argv)
        self.assertEqual(FINDING_RE.findall(out), [(ALLOW, "AWS access key ID")])
        self.assertEqual(code, 1)

    def test_all_files_scans_an_edit_to_the_allow_file_not_yet_committed(self):
        # The walk left the working-tree copy to the committed one, so a key
        # added to the allow file and not committed went unreported, where
        # the same key in any other file was reported.
        self.repo.write(ALLOW, b"# vouches for nothing\n")
        self.repo.commit("add the allow file")
        self.repo.write(ALLOW, f"# vouches for nothing\n{AWS_KEY}\n".encode())
        code, out = self.scan("--mode", "all-files")
        self.assertEqual(FINDING_RE.findall(out), [(ALLOW, "AWS access key ID")])
        self.assertIn(f"::error file={ALLOW},line=2::", out)
        self.assertEqual(code, 1)
        # Committed, then moved down a line in the working tree: reported
        # once, where the working tree has it.
        self.repo.commit("commit the key")
        self.repo.write(ALLOW, f"# vouches for nothing\n\n{AWS_KEY}\n".encode())
        code, out = self.scan("--mode", "all-files")
        self.assertEqual(FINDING_RE.findall(out), [(ALLOW, "AWS access key ID")])
        self.assertIn(f"::error file={ALLOW},line=3::", out)
        self.assertEqual(code, 1)

    def test_all_files_reads_the_allow_file_from_root(self):
        # git read HEAD:<path> from the top of the repository, while the walk
        # lists paths from --root. With --root sub the list came from the
        # top-level file, and the walk skipped sub's own copy as that file.
        self.repo.write(ALLOW, b"# the top-level list\n")
        self.repo.write(f"sub/{ALLOW}", f"{AWS_KEY}\n".encode())
        self.repo.commit("an allow file at the top and one in sub")
        root = str(self.repo.path / "sub")
        argv = ["--mode", "all-files", "--root", root, "--allow-file", ALLOW]
        code, out, err = run_main(argv)
        self.assertNotIn(AWS_KEY, out + err)
        self.assertEqual(FINDING_RE.findall(out), [(ALLOW, "AWS access key ID")])
        self.assertIn(f"Allow file {ALLOW} at HEAD: 1 entry, 0 match", out)
        self.assertEqual(code, 1)

    def test_stdin_knows_the_allow_file_by_its_path_in_the_diff(self):
        # The branch's own copy handed over by mistake, under another name.
        # Its own line is still reported, whatever the copy is called.
        base = self.repo.head()
        self.vouch_for_a_real_key()
        diff = rc.get_diff_via_git(base, str(self.repo.path))
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "head-allow.txt"
            copy.write_bytes((self.repo.path / ALLOW).read_bytes())
            code, out, err = run_main(["--allow-file", str(copy)], stdin_text=diff)
        self.assertEqual(FINDING_RE.findall(out), [(ALLOW, "AWS access key ID")])
        self.assertEqual(code, 1)
        self.assertNotIn(AWS_KEY, out + err)

    def test_allow_path_names_the_allow_file_in_the_diff(self):
        diff = one_file_diff(ALLOW, AWS_KEY) + one_file_diff("cfg/allow.txt", AWS_KEY)
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "copy.txt"
            copy.write_text(f"{AWS_KEY}\n", encoding="utf-8")
            for extra, own in [
                ([], ALLOW),
                (["--allow-path", "cfg/allow.txt"], "cfg/allow.txt"),
            ]:
                with self.subTest(extra=extra):
                    argv = ["--allow-file", str(copy), *extra]
                    code, out, _err = run_main(argv, stdin_text=diff)
                    self.assertEqual(
                        FINDING_RE.findall(out), [(own, "AWS access key ID")]
                    )

    def test_stdin_reads_no_allow_file_unless_one_is_named(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ALLOW).write_text(f"{MODULE}\n", encoding="utf-8")
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                diff = one_file_diff("app.py", f"import pkg.{MODULE}")
                code, out, _err = run_main([], stdin_text=diff)
            finally:
                os.chdir(cwd)
        self.assertEqual(code, 1)
        self.assertNotIn("Allow file", out)

    def test_the_allow_options_are_refused_where_they_mean_nothing(self):
        listed = ["--allow-file", ALLOW]
        base = ["--base", "main", *listed]
        for argv in [
            ["--allow-file", "a\n::stop-commands::x"],
            [*listed, "--allow-ref", "main"],
            ["--base", "main", "--allow-ref", "main"],
            ["--mode", "all-files", *base, "--allow-ref", "main"],
            [*base, "--allow-ref=-x"],
            [*base, "--allow-ref", "main\n::warning::x"],
            ["--allow-path", ALLOW],
            [*base, "--allow-path", ALLOW],
            ["--mode", "all-files", *listed, "--allow-path", ALLOW],
        ]:
            with self.subTest(argv=argv):
                git = mock.patch.object(rc, "_git", side_effect=AssertionError("git"))
                with git, self.assertRaises(SystemExit) as ctx:
                    run_main([*argv, "--diff-file", os.devnull])
                self.assertEqual(ctx.exception.code, 2)


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

    def test_a_branch_is_fetched_and_read_by_its_full_name(self):
        # git reads a short origin/<name> as a tag or a local branch of that
        # name first. ShadowedRefTests and ActionStepTests show what that did.
        self.assertTrue(
            any('base="refs/remotes/origin/$BASE_REF"' in ln for ln in self.code)
        )
        self.assertTrue(
            any('refspec="+refs/heads/$BASE_REF:$base"' in ln for ln in self.code)
        )
        short = [
            ln for ln in self.code if re.search(r"(?<!refs/remotes/)origin/\$", ln)
        ]
        self.assertEqual(short, [])

    def test_skipping_the_scanner_files_is_opt_in(self):
        text = (THIS_DIR / "action.yml").read_text(encoding="utf-8")
        declared = re.search(r"\n  skip-scanner-files:\n(?:    .*\n)+", text)
        self.assertIsNotNone(declared)
        self.assertIn("default: 'false'", declared.group(0))
        self.assertTrue(any("--skip-scanner-files" in ln for ln in self.code))

    def test_the_allow_file_is_read_by_default(self):
        text = (THIS_DIR / "action.yml").read_text(encoding="utf-8")
        declared = re.search(r"\n  allow-file:\n(?:    .*\n)+", text)
        self.assertIsNotNone(declared)
        self.assertIn("default: .redaction-allow", declared.group(0))
        self.assertTrue(any('"--allow-file=$ALLOW_FILE"' in ln for ln in self.code))
        self.assertTrue(
            any('"--summary-file=$GITHUB_STEP_SUMMARY"' in ln for ln in self.code)
        )

    def test_a_push_elsewhere_reads_the_allow_file_from_the_default_branch(self):
        # ActionStepTests set these variables by hand, so guard their source.
        text = (THIS_DIR / "action.yml").read_text(encoding="utf-8")
        for mapping in [
            "EVENT_NAME: ${{ github.event_name }}",
            "GIT_REF: ${{ github.ref }}",
            "DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}",
        ]:
            self.assertIn(mapping, text)
        # By its full name: a tag or a local branch called origin/main would
        # win over a short one.
        allow_ref = '"--allow-ref=refs/remotes/origin/$DEFAULT_BRANCH"'
        self.assertTrue(any(allow_ref in ln for ln in self.code))

    def test_the_pull_request_head_reaches_the_scanner(self):
        self.assertTrue(
            any("github.event.pull_request.head.sha" in ln for ln in self.code)
        )
        self.assertTrue(any("--pr-head" in ln for ln in self.code))

    def test_the_action_leaves_the_caller_s_python_alone(self):
        # setup-python's default update-environment: true put 3.12 first on
        # the job's PATH, so every later step in the caller's job ran on it.
        text = (THIS_DIR / "action.yml").read_text(encoding="utf-8")
        setup = text[text.index("- name: Set up Python") : text.index("- name: Scan")]
        self.assertIn("id: py", setup)
        self.assertIn("update-environment: false", setup)
        self.assertIn("PYTHON: ${{ steps.py.outputs.python-path }}", text)
        step = run_block(THIS_DIR / "action.yml", "Scan for private-content shapes")
        commands = [ln for ln in step.splitlines() if not ln.lstrip().startswith("#")]
        self.assertEqual(
            [ln for ln in commands if re.search(r"(?<![-\w])python(?![-\w])", ln)], []
        )
        self.assertTrue(any('"$PYTHON" "' in ln for ln in commands))


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
        self.assertIn('origin -- "$refspec"', code[fetch])


def run_block(path: Path, step_name: str) -> str:
    """Return the `run: |` block of the step with this name, dedented."""
    lines = path.read_text(encoding="utf-8").splitlines()
    name = next(i for i, ln in enumerate(lines) if ln.strip() == f"- name: {step_name}")
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
        raise AssertionError(f"{step_name}: an expression is left in its run block")
    return script


def run_bash(script: Path, cwd: Path, env: dict[str, str]) -> tuple[int, str]:
    result = subprocess.run(
        [BASH or "bash", script.as_posix()],
        cwd=cwd,
        env={**os.environ, **env},
        capture_output=True,
        check=False,
    )
    return result.returncode, rc._text(result.stdout + result.stderr)


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
        cls.script = cls.tmp / "step.sh"
        step = run_block(THIS_DIR / "action.yml", "Scan for private-content shapes")
        cls.script.write_text(step, encoding="utf-8", newline="\n")
        (cls.tmp / "upstream").mkdir()
        up = ScratchRepo(str(cls.tmp / "upstream"))
        cls.base = up.head()
        up.write("notes.txt", f"host {IP}\n".encode())
        up.commit("add a host")
        cls.url = up.path.as_uri()
        # A second upstream whose main vouches for IP.
        (cls.tmp / "vouched").mkdir()
        vouched = ScratchRepo(str(cls.tmp / "vouched"))
        vouched.write(ALLOW, f"{IP}{FIXTURE_OK}\n".encode())
        vouched.commit("main vouches for one address")
        cls.vouched_url = vouched.path.as_uri()

    def clone(self, url: str = "") -> Path:
        runner = Path(tempfile.mkdtemp(dir=self.tmp))
        git_out(self.tmp, "clone", "-q", url or self.url, str(runner))
        return runner

    def branch_pushes(self, branch: str = "feature") -> tuple[Path, str]:
        """Clone the vouched upstream and add two pushes to a branch: the
        first vouches for OTHER_IP on the branch alone, the second uses both
        addresses. Returns the clone and the first push's commit."""
        runner = self.clone(self.vouched_url)
        identity = ["-c", "user.email=test@example.com", "-c", "user.name=test"]
        git_out(runner, "checkout", "-q", "-b", branch)
        both = f"{IP}{FIXTURE_OK}\n{OTHER_IP}{FIXTURE_OK}\n"
        (runner / ALLOW).write_text(both, encoding="utf-8")
        git_out(runner, "add", ALLOW)
        git_out(runner, *identity, "commit", "-qm", "push 1: vouch on the branch")
        before = git_out(runner, "rev-parse", "HEAD")
        (runner / "more.txt").write_text(
            f"host {IP}\nhost {OTHER_IP}\n", encoding="utf-8"
        )
        git_out(runner, "add", "more.txt")
        git_out(runner, *identity, "commit", "-qm", "push 2: use both")
        return runner, before

    def run_step(self, cwd: Path, **env: str) -> tuple[int, str, dict[str, str]]:
        """Run the step in cwd. Returns its exit code, output and step outputs."""
        outputs = Path(tempfile.mkdtemp(dir=self.tmp)) / "github_output"
        outputs.touch()
        code, out = run_bash(
            self.script,
            cwd,
            {
                # What the Set up Python step's python-path output gives it.
                "PYTHON": Path(sys.executable).as_posix(),
                "FAIL_ON": "match",
                "SCAN_MODE": "added-lines",
                "PATTERNS_FILE": "",
                "ALLOW_FILE": "",
                "SKIP_SCANNER_FILES": "false",
                "BASE_REF": "",
                "PR_BASE_REF": "",
                "PR_HEAD_SHA": "",
                "EVENT_NAME": "",
                "GIT_REF": "",
                "DEFAULT_BRANCH": "",
                "GITHUB_OUTPUT": outputs.as_posix(),
                # Never the summary of the CI job running these tests.
                "GITHUB_STEP_SUMMARY": outputs.with_name("step_summary").as_posix(),
                "RUNNER_TEMP": self.tmp.as_posix(),
                **env,
            },
        )
        lines = outputs.read_text(encoding="utf-8").splitlines()
        return code, out, dict(ln.split("=", 1) for ln in lines if "=" in ln)

    def test_a_base_ref_that_looks_like_an_option_runs_no_command(self):
        # Over a file or ssh remote, git fetch ran --upload-pack's command.
        runner = self.clone()
        base_ref = "--upload-pack=touch${IFS}INJECTED;git-upload-pack"
        code, out, _outputs = self.run_step(runner, BASE_REF=base_ref)
        self.assertEqual(code, 2, out)
        self.assertIn("::error::base-ref cannot start with '-'", out)
        self.assertFalse((runner / "INJECTED").exists())

    def test_a_base_ref_with_a_newline_cannot_forge_a_command(self):
        runner = self.clone()
        code, out, _outputs = self.run_step(runner, BASE_REF="main\n::warning::x")
        self.assertEqual(code, 2, out)
        self.assertNotIn("\n::warning::", "\n" + out)

    def upstream_branch(self, branch: str) -> tuple[ScratchRepo, str]:
        """An upstream whose branch adds a host that main doesn't have.
        Returns the upstream, back on main, and the branch's head."""
        up = ScratchRepo(tempfile.mkdtemp(dir=self.tmp))
        git_out(up.path, "checkout", "-q", "-b", branch)
        up.write("more.txt", f"host {IP}\n".encode())
        up.commit("add a host")
        head = up.head()
        git_out(up.path, "checkout", "-q", "main")
        return up, head

    def assert_the_host_is_reported(self, code: int, out: str) -> None:
        self.assertEqual(code, 1, out)
        self.assertEqual(
            FINDING_RE.findall(out), [("more.txt", "private/link-local IP")]
        )

    def test_a_push_to_a_branch_named_origin_main_is_diffed_against_main(self):
        # actions/checkout runs `checkout -B origin/main` for this push. The
        # step read its base origin/main as that local branch, so the range
        # was HEAD..HEAD and nothing was scanned.
        up, _head = self.upstream_branch("origin/main")
        url = up.path.as_uri()
        runner = checkout_like_actions(self.tmp, url, branch="origin/main")
        code, out, _outputs = self.run_step(runner, BASE_REF="main")
        self.assert_the_host_is_reported(code, out)

    def test_a_tag_named_origin_main_at_the_head_leaves_the_push_in_range(self):
        up, head = self.upstream_branch("feature")
        git_out(up.path, "tag", "origin/main", head)
        url = up.path.as_uri()
        runner = checkout_like_actions(self.tmp, url, branch="feature")
        code, out, _outputs = self.run_step(runner, BASE_REF="main")
        self.assert_the_host_is_reported(code, out)

    def test_a_tag_and_a_branch_named_origin_main_leave_the_pull_request_in(self):
        # The pull request forked from an older main. A tag origin/main at its
        # head passed for a rewritten base and narrowed the scan to main's own
        # newer commits.
        up, head = self.upstream_branch("feature")
        up.write("later.txt", b"later\n")
        up.commit("main moves on")
        git_out(up.path, "tag", "origin/main", head)
        git_out(up.path, "checkout", "-q", "--detach")
        git_out(up.path, "merge", "-q", "--no-ff", "-m", "test merge", head)
        merge = up.head()
        git_out(up.path, "update-ref", "refs/pull/1/merge", merge)
        git_out(up.path, "checkout", "-q", "main")
        runner = checkout_like_actions(self.tmp, up.path.as_uri(), merge=merge)
        git_out(runner, "branch", "origin/main", head)
        pull_request = {"BASE_REF": "main", "PR_BASE_REF": "main"}
        code, out, _outputs = self.run_step(runner, PR_HEAD_SHA=head, **pull_request)
        self.assert_the_host_is_reported(code, out)
        self.assertIn("test-merge commit against its first parent", out)

    def test_a_tag_named_like_the_base_branch_does_not_stop_its_fetch(self):
        # A fetch of the short name main took origin's tag main and left the
        # checkout's origin/main as it was. Here main is rewritten after the
        # checkout to purge a host the branch still carries, which only the
        # rewritten main puts back in range.
        up = ScratchRepo(tempfile.mkdtemp(dir=self.tmp))
        root = up.head()
        up.write("leak.txt", f"nas {IP}\n".encode())
        up.commit("a host lands on main")
        git_out(up.path, "checkout", "-q", "-b", "feature")
        up.write("f.txt", b"clean\n")
        up.commit("clean work")
        git_out(up.path, "checkout", "-q", "main")
        git_out(up.path, "tag", "main", root)
        url = up.path.as_uri()
        runner = checkout_like_actions(self.tmp, url, branch="feature")
        git_out(up.path, "reset", "-q", "--hard", root)
        up.write("o.txt", b"other\n")
        up.commit("main rewritten, the host purged")
        code, out, _outputs = self.run_step(runner, BASE_REF="main")
        self.assertEqual(code, 1, out)
        self.assertEqual(
            FINDING_RE.findall(out), [("leak.txt", "private/link-local IP")]
        )
        self.assertEqual(
            git_out(runner, "rev-parse", "refs/remotes/origin/main"), up.head()
        )

    def test_the_step_reports_its_exit_code_and_output(self):
        # ci.yml asserts on these. A step outcome alone could not tell a
        # finding (1) from a scan that never ran (2).
        runner = self.clone()
        code, out, outputs = self.run_step(runner, BASE_REF=self.base)
        self.assertEqual(code, 1, out)
        self.assertEqual(outputs["exit-code"], "1")
        report = Path(outputs["report"]).read_text(encoding="utf-8")
        self.assertEqual(
            FINDING_RE.findall(report), [("notes.txt", "private/link-local IP")]
        )
        code, out, outputs = self.run_step(runner, BASE_REF="")
        self.assertEqual((code, outputs["exit-code"]), (2, "2"), out)

    def test_no_python_path_is_a_scan_that_cannot_run(self):
        code, out, outputs = self.run_step(self.clone(), BASE_REF=self.base, PYTHON="")
        self.assertEqual((code, outputs["exit-code"]), (2, "2"), out)
        self.assertIn("::error::The Set up Python step gave no python-path", out)

    def test_the_allow_file_is_read_from_the_base_and_counted(self):
        runner = self.clone()
        identity = ["-c", "user.email=test@example.com", "-c", "user.name=test"]
        (runner / ALLOW).write_text(f"{IP}\n", encoding="utf-8")
        git_out(runner, "add", ALLOW)
        git_out(runner, *identity, "commit", "-qm", "allow the host")
        base = git_out(runner, "rev-parse", "HEAD")
        (runner / "more.txt").write_text(f"host {IP}\n", encoding="utf-8")
        git_out(runner, "add", "more.txt")
        git_out(runner, *identity, "commit", "-qm", "use it again")
        summary = Path(tempfile.mkdtemp(dir=self.tmp)) / "summary.md"
        code, out, outputs = self.run_step(
            runner,
            BASE_REF=base,
            ALLOW_FILE=ALLOW,
            GITHUB_STEP_SUMMARY=summary.as_posix(),
        )
        self.assertEqual((code, outputs["exit-code"]), (0, "0"), out)
        counted = "1 entry, 1 match(es) suppressed."
        self.assertIn(counted, Path(outputs["report"]).read_text(encoding="utf-8"))
        self.assertIn(counted, summary.read_text(encoding="utf-8"))
        # An empty input turns the allow file off.
        code, out, _outputs = self.run_step(runner, BASE_REF=base)
        self.assertEqual(code, 1, out)

    def test_a_push_reads_the_allow_file_the_default_branch_has(self):
        runner, before = self.branch_pushes()
        push = {"BASE_REF": before, "ALLOW_FILE": ALLOW, "EVENT_NAME": "push"}
        # To another branch, before is the pusher's own last push, so the
        # list comes from main's tip, which vouches for IP alone.
        code, out, _outputs = self.run_step(
            runner, GIT_REF="refs/heads/feature", DEFAULT_BRANCH="main", **push
        )
        self.assertEqual(code, 1, out)
        self.assertEqual(
            FINDING_RE.findall(out), [("more.txt", "private/link-local IP")]
        )
        self.assertIn("::error file=more.txt,line=2::", out)
        main = "(refs/remotes/origin/main): 1 entry, 1 match(es) suppressed."
        self.assertIn(main, out)
        # To main itself, before is main's own history.
        code, out, _outputs = self.run_step(
            runner, GIT_REF="refs/heads/main", DEFAULT_BRANCH="main", **push
        )
        self.assertEqual(code, 0, out)
        self.assertIn(f"at {before[:12]}: 2 entries, 2 match(es) suppressed.", out)

    def test_a_ref_named_origin_main_never_gives_the_push_its_own_list(self):
        # A push to a branch named origin/main gets a local branch of that
        # name from actions/checkout, and fetch-depth: 0 brings a tag of that
        # name. The step read the list from origin/main, which git took for
        # either one, the pushed head, whose own entries then counted.
        for kind, branch in [("branch", "origin/main"), ("tag", "feature")]:
            with self.subTest(kind=kind):
                runner, before = self.branch_pushes(branch)
                if kind == "tag":
                    git_out(runner, "tag", "origin/main", "HEAD")
                code, out, _outputs = self.run_step(
                    runner,
                    BASE_REF=before,
                    ALLOW_FILE=ALLOW,
                    EVENT_NAME="push",
                    GIT_REF=f"refs/heads/{branch}",
                    DEFAULT_BRANCH="main",
                )
                self.assertEqual(code, 1, out)
                self.assertEqual(
                    FINDING_RE.findall(out), [("more.txt", "private/link-local IP")]
                )
                self.assertIn("::error file=more.txt,line=2::", out)
                main = "(refs/remotes/origin/main): 1 entry, 1 match(es) suppressed."
                self.assertIn(main, out)

    def test_a_ref_named_origin_main_leaves_a_push_diffed_against_main(self):
        # The README's base-ref for a push to a branch other than main. git
        # read the base origin/main as the pushed head, so the range was
        # HEAD..HEAD and the whole push went unscanned.
        for kind, branch in [("branch", "origin/main"), ("tag", "feature")]:
            with self.subTest(kind=kind):
                runner, _before = self.branch_pushes(branch)
                if kind == "tag":
                    git_out(runner, "tag", "origin/main", "HEAD")
                code, out, _outputs = self.run_step(
                    runner,
                    BASE_REF="main",
                    ALLOW_FILE=ALLOW,
                    EVENT_NAME="push",
                    GIT_REF=f"refs/heads/{branch}",
                    DEFAULT_BRANCH="main",
                )
                self.assertEqual(code, 1, out)
                self.assertEqual(
                    FINDING_RE.findall(out), [("more.txt", "private/link-local IP")]
                )
                self.assertIn("::error file=more.txt,line=2::", out)
                main = "(refs/remotes/origin/main): 1 entry, 1 match(es) suppressed."
                self.assertIn(main, out)

    def upstream_with_an_empty_list(self) -> tuple[ScratchRepo, str]:
        """An upstream whose main has an allow file that vouches for nothing.
        Returns it and main's tip."""
        up = ScratchRepo(tempfile.mkdtemp(dir=self.tmp))
        up.write(ALLOW, b"# nothing vouched for on main\n")
        up.commit("main: an empty list")
        return up, up.head()

    def tag_origin_main_vouching_for_ip(self, up: ScratchRepo, at: str) -> None:
        """Tag a child of at, on no branch, whose allow file vouches for IP."""
        git_out(up.path, "checkout", "-q", "--detach", at)
        up.write(ALLOW, f"{IP}{FIXTURE_OK}\n".encode())
        up.commit("vouch, on a tag only")
        git_out(up.path, "tag", "origin/main", up.head())
        git_out(up.path, "checkout", "-q", "main")

    def feature_using_ip(self, up: ScratchRepo, at: str) -> str:
        """Fork feature from at and use IP there. Returns its head."""
        git_out(up.path, "checkout", "-q", "-b", "feature", at)
        up.write("more.txt", f"host {IP}\n".encode())
        up.commit("use it")
        head = up.head()
        git_out(up.path, "checkout", "-q", "main")
        return head

    def test_a_tag_named_origin_main_never_gives_a_head_checkout_its_list(self):
        # pull_request_target, or pull_request with ref: head.sha. The list
        # comes from the base as it is now, which git took to be the tag.
        up, main_tip = self.upstream_with_an_empty_list()
        self.tag_origin_main_vouching_for_ip(up, main_tip)
        head = self.feature_using_ip(up, main_tip)
        url = up.path.as_uri()
        runner = checkout_like_actions(self.tmp, url, branch="feature")
        code, out, _outputs = self.run_step(
            runner,
            BASE_REF="main",
            PR_BASE_REF="main",
            PR_HEAD_SHA=head,
            ALLOW_FILE=ALLOW,
            EVENT_NAME="pull_request_target",
            GIT_REF="refs/heads/main",
            DEFAULT_BRANCH="main",
        )
        self.assertEqual(code, 1, out)
        self.assertEqual(
            FINDING_RE.findall(out), [("more.txt", "private/link-local IP")]
        )
        self.assertIn(
            f"at {main_tip[:12]} (refs/remotes/origin/main): 0 entries, 0 ", out
        )

    def test_a_tag_named_origin_main_off_an_older_main_never_gives_its_list(self):
        # The default pull_request checkout. The tag doesn't hold main's tip,
        # so the scan took it for a rewritten base, widened, and read the
        # list from the tag.
        up, old = self.upstream_with_an_empty_list()
        up.write("later.txt", b"later\n")
        up.commit("main moves on")
        main_tip = up.head()
        self.tag_origin_main_vouching_for_ip(up, old)
        head = self.feature_using_ip(up, main_tip)
        git_out(up.path, "checkout", "-q", "--detach", main_tip)
        git_out(up.path, "merge", "-q", "--no-ff", "-m", "test merge", head)
        merge = up.head()
        git_out(up.path, "update-ref", "refs/pull/1/merge", merge)
        git_out(up.path, "checkout", "-q", "main")
        runner = checkout_like_actions(self.tmp, up.path.as_uri(), merge=merge)
        code, out, _outputs = self.run_step(
            runner,
            BASE_REF="main",
            PR_BASE_REF="main",
            PR_HEAD_SHA=head,
            ALLOW_FILE=ALLOW,
            EVENT_NAME="pull_request",
            GIT_REF="refs/pull/1/merge",
            DEFAULT_BRANCH="main",
        )
        self.assertEqual(code, 1, out)
        self.assertEqual(
            FINDING_RE.findall(out), [("more.txt", "private/link-local IP")]
        )
        self.assertIn("test-merge commit against its first parent", out)
        built_on = f"at {main_tip[:12]} (the commit the test merge was built on)"
        self.assertIn(f"{built_on}: 0 entries, 0 ", out)

    def test_a_shallow_single_branch_checkout_still_reads_the_default_branch(self):
        # Two commits deep with no refspec for main, so origin/main exists
        # only if the step fetches it into place itself.
        upstream = Path(tempfile.mkdtemp(dir=self.tmp))
        git_out(upstream, "init", "-q", "--bare")
        runner, before = self.branch_pushes()
        git_out(runner, "push", "-q", upstream.as_uri(), "main", "feature")
        shallow = Path(tempfile.mkdtemp(dir=self.tmp))
        git_out(
            self.tmp,
            "clone",
            "-q",
            "--depth=2",
            "--single-branch",
            "--branch=feature",
            upstream.as_uri(),
            str(shallow),
        )
        self.assertNotIn("origin/main", git_out(shallow, "branch", "-r"))
        code, out, _outputs = self.run_step(
            shallow,
            BASE_REF=before,
            ALLOW_FILE=ALLOW,
            EVENT_NAME="push",
            GIT_REF="refs/heads/feature",
            DEFAULT_BRANCH="main",
        )
        self.assertEqual(code, 1, out)
        self.assertEqual(
            FINDING_RE.findall(out), [("more.txt", "private/link-local IP")]
        )
        main = "(refs/remotes/origin/main): 1 entry, 1 match(es) suppressed."
        self.assertIn(main, out)

    def test_a_default_branch_it_cannot_read_means_no_allow_file(self):
        # Never before in its place, which vouches for both addresses.
        runner, before = self.branch_pushes()
        code, out, _outputs = self.run_step(
            runner,
            BASE_REF=before,
            ALLOW_FILE=ALLOW,
            EVENT_NAME="push",
            GIT_REF="refs/heads/feature",
            DEFAULT_BRANCH="trunk",
        )
        self.assertEqual(code, 1, out)
        self.assertEqual(len(FINDING_RE.findall(out)), 2, out)
        self.assertIn("::warning::Could not fetch the default branch", out)
        self.assertIn("::notice::No allow file was read", out)


@unittest.skipUnless(BASH, "needs bash, as a runner has")
class CISelfTestTests(unittest.TestCase):
    """ci.yml's self-test assertions, run on the outputs they check."""

    CI = THIS_DIR / ".github" / "workflows" / "ci.yml"
    DIRTY = "a" * 40

    def check(self, step_name: str, report_text: str, **env: str) -> int:
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "assert.sh"
            block = run_block(self.CI, step_name)
            script.write_text(block, encoding="utf-8", newline="\n")
            report = Path(tmp) / "report"
            report.write_text(report_text, encoding="utf-8")
            env = {"REPORT": report.as_posix(), "DIRTY_SHA": self.DIRTY, **env}
            code, _out = run_bash(script, Path(tmp), env)
        return code

    def finding(self, commit: str = "") -> str:
        added = f" added in commit {commit[:12]}" if commit else ""
        return (
            "::error file=.fixture/probe.txt,line=2::Possible absolute home path"
            f"{added}: hmac:0123456789ab (masked, not the real value).\n"
        )

    def test_the_dirty_run_must_exit_1_and_name_the_fixture(self):
        step = "Assert the dirty fixture was caught"
        self.assertEqual(self.check(step, self.finding(), EXIT_CODE="1"), 0)
        # A scan that cannot run also fails the step, and used to pass here.
        self.assertNotEqual(self.check(step, self.finding(), EXIT_CODE="2"), 0)
        self.assertNotEqual(
            self.check(step, "Redaction gate: clean.\n", EXIT_CODE="1"), 0
        )

    def test_the_history_run_must_name_the_dirty_commit(self):
        step = "Assert the finding names the commit that added the shape"
        found = self.finding(self.DIRTY)
        self.assertEqual(self.check(step, found, EXIT_CODE="1"), 0)
        other = self.finding("b" * 40)
        self.assertNotEqual(self.check(step, other, EXIT_CODE="1"), 0)
        self.assertNotEqual(self.check(step, found, EXIT_CODE="2"), 0)

    def test_the_clean_run_must_exit_0(self):
        step = "Assert the clean fixture passed"
        self.assertEqual(self.check(step, "", EXIT_CODE="0"), 0)
        self.assertNotEqual(self.check(step, "", EXIT_CODE="2"), 0)

    @unittest.skipUnless(shutil.which("python"), "the blocks call `python`")
    def test_the_caller_s_python_must_survive_the_action(self):
        text = self.CI.read_text(encoding="utf-8")
        pin = text.index("python-version: '3.13'")
        self.assertLess(pin, text.index("uses: ./"))  # pinned before any run
        with tempfile.TemporaryDirectory() as tmp:
            record = Path(tmp) / "record.sh"
            block = run_block(self.CI, "Record the caller's Python")
            record.write_text(block, encoding="utf-8", newline="\n")
            outputs = Path(tmp) / "outputs"
            outputs.touch()
            env = {"GITHUB_OUTPUT": outputs.as_posix()}
            self.assertEqual(run_bash(record, Path(tmp), env)[0], 0)
            lines = outputs.read_text(encoding="utf-8").splitlines()
            before = dict(ln.split("=", 1) for ln in lines)
        step = "Assert the action left the caller's Python alone"
        same = {"BEFORE": before["python"], "BEFORE_LOCATION": before["location"]}
        self.assertEqual(self.check(step, "", **same), 0)
        # What the action's own setup-python step used to leave behind.
        moved = {**same, "BEFORE": "3.12.0 /opt/hostedtoolcache/Python/3.12.0"}
        self.assertNotEqual(self.check(step, "", **moved), 0)

    def test_pull_requests_scan_the_untouched_test_merge(self):
        # The fixture commits sit on top of the test merge, so without this
        # step CI never ran the first-parent range a pull request takes.
        text = self.CI.read_text(encoding="utf-8")
        untouched = text.index("- name: Run the action on the untouched checkout")
        fixture = text.index("- name: Add a fixture commit")
        step = text[untouched:fixture]
        self.assertLess(untouched, fixture)
        self.assertIn("if: github.event_name == 'pull_request'", step)
        self.assertIn("uses: ./", step)
        self.assertNotIn("continue-on-error", step)


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
