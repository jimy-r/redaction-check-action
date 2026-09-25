# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This file was started during the work toward v1.1.0. Earlier releases, and the fixes already on their way to v1.1.0, are described in the commit history.

## [Unreleased]

### Added

- An allow file for values that are safe every time, such as a module path that the `.local` check reads as a host. The new `allow-file` input (default `.redaction-allow`) and `--allow-file` option take one exact value per line. A finding is let through only when the text its pattern matched equals an entry, case and all. Entries shorter than four characters, holding whitespace or holding U+FFFD (what a byte that isn't valid text decodes to) are ignored, the list stops at 200 entries, and each ignored line gets a warning that names the line but never repeats its text.
- In `added-lines` mode the allow file is read from a commit outside the change, for the net diff and every commit in the range alike, so an entry a pull request or push adds lets nothing through until it has landed. A pull request's test merge reads the commit it was built on. Any other range reads the base as it is now, never the merge base. A push to a branch other than the default one reads the default branch's tip, through the new `--allow-ref` option. When that commit isn't in the clone, no allow file is read and a notice says so.
- `all-files` mode reads the allow file as `HEAD` commits it, and scans that committed copy as the allow file itself, whatever its size. A diff on stdin reads the allow file from disk as given, and knows the allow file's own lines by their path in the diff (the new `--allow-path` option, default `.redaction-allow`). The list never applies to a file with the allow file's name, so a secret pasted into the allow file is still reported.
- The log and the job summary report how many matches the allow file let through. The new `--summary-file` option writes the summary, and the action points it at `$GITHUB_STEP_SUMMARY`.

### Security

- A short ref could be shadowed. The action named the base as `origin/<base-ref>`, and git reads that short name as a tag or a local branch called `origin/main` before the branch on origin, with only a warning. A push to a branch named `origin/main` leaves such a local branch in the checkout, and `fetch-depth: 0` brings every tag. With one in place, a push with `base-ref: main` diffed its head against itself and scanned nothing, and a pull request from an older `main`, with a tag at its head, was scanned without its own lines. Released versions up to v1.0.1 diff against `origin/<base-ref>` and are open to the same thing.
- The base is now fetched and passed in full, as `refs/remotes/origin/<base-ref>`, and so is the default branch that a push to any other branch reads the allow file from. A fetch by the short name could also take origin's tag of that name in place of its branch.
- The script refuses a `--base` or `--allow-ref` that could be more than one ref, and a full ref name that isn't there but that git would read as some other ref. The scan exits 2 and names the refs. A full name that exists is read as itself, as git reads it, and a full commit SHA is always that commit.
