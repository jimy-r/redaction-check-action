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
import io
import subprocess
import sys
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

    def test_self_paths_are_excluded(self):
        diff = (
            "diff --git a/redaction_check.py b/redaction_check.py\n"
            "index 1..2 100644\n"
            "--- a/redaction_check.py\n"
            "+++ b/redaction_check.py\n"
            "@@ -0,0 +1,1 @@\n"
            "+token " + "sk-ant-" + "api03EXAMPLEKEY0000000\n"
        )
        self.assertEqual(rc.scan_added_lines(diff), [])

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

    def test_all_files_mode_via_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q"], cwd=tmp, check=True)
            dirty = Path(tmp) / "dirty.txt"
            dirty.write_text("internal host " + "10.20.30.40" + "\n", encoding="utf-8")
            subprocess.run(["git", "add", "dirty.txt"], cwd=tmp, check=True)
            code, out, _err = run_main(["--mode", "all-files", "--root", tmp])
        self.assertEqual(code, 1)
        self.assertIn("private/link-local IP", out)


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

    def test_the_pull_request_head_reaches_the_scanner(self):
        self.assertTrue(
            any("github.event.pull_request.head.sha" in ln for ln in self.code)
        )
        self.assertTrue(any("--pr-head" in ln for ln in self.code))


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
