# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This file was started during the work toward v1.1.0. Earlier releases, and the fixes already on their way to v1.1.0, are described in the commit history.

## [Unreleased]

### Added

- An allow file for values that are safe every time, such as a module path that the `.local` check reads as a host. The new `allow-file` input (default `.redaction-allow`) and `--allow-file` option take one exact value per line. A finding is let through only when the text its pattern matched equals an entry, case and all. Entries shorter than four characters or holding whitespace are ignored, the list stops at 200 entries, and each ignored line gets a warning that names the line but never repeats its text.
- In `added-lines` mode the allow file is read from a commit outside the change, for the net diff and every commit in the range alike, so an entry a pull request or push adds lets nothing through until it has landed. A pull request's test merge reads the commit it was built on. Any other range reads the base as it is now, never the merge base. A push to a branch other than the default one reads the default branch's tip, through the new `--allow-ref` option. When that commit isn't in the clone, no allow file is read and a notice says so.
- `all-files` mode reads the allow file as `HEAD` commits it. A diff on stdin reads the allow file from disk as given. The list never applies to a file with the allow file's name, so a secret pasted into the allow file is still reported.
- The log and the job summary report how many matches the allow file let through. The new `--summary-file` option writes the summary, and the action points it at `$GITHUB_STEP_SUMMARY`.
