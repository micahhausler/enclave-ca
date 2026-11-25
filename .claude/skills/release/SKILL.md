---
name: release
description: Cut an enclave-ca release - bump Version.swift, tag, publish a source-only GitHub release, and update the Homebrew formula. Use when I say "release", "cut a release", "ship vX.Y.Z", or "tag vX.Y.Z".
---

# Release enclave-ca

A release is a `vX.Y.Z` tag on `main`, a GitHub release, and a Homebrew formula that builds that release from source.
`scripts/release.sh` does the tag, release, and formula PR; this skill wraps it with the version bump and the checks around it.

The release carries no binaries, only `enclave-ca-X.Y.Z.tar.gz` (`git archive` of the tagged commit, which the formula builds) and its `SHA256SUMS`.
Releases are cut from a Mac and published as me, never from CI.

## Steps

1. **Pick the version.**
   Use the version I gave; otherwise show the latest tag (`git tag --sort=-v:refname | head -1`) and the commits since it, propose the next semver, and wait for my answer.

2. **Bump `Sources/EnclaveCA/Version.swift`.**
   Skip this when `main` already says the version.
   Otherwise, in a worktree `.worktree/release-vX.Y.Z` off `origin/main`, set `enclaveCAVersion` to the version, run `swift build` and `swift test`, and commit `enclave-ca: version X.Y.Z`.
   Show me the commit message and PR text, push after my yes, and open the PR with `gh-bot pr create --reviewer micahhausler`.
   Wait for me to say it is merged.

3. **Dry run.**
   In the main checkout, `git checkout main` and `git pull --ff-only`, then run `scripts/release.sh --dry-run X.Y.Z`.
   It must finish with no warnings.
   Show me the `SHA256SUMS` it printed and the last lines of its output.

4. **Release.**
   After my yes, run `scripts/release.sh X.Y.Z`.
   It pushes the tag as me, creates the release, checks the uploaded source tarball's sha256, and opens the formula PR through gh-bot, which asks 1Password for approval.
   Report the release URL and the formula PR URL.
   If it fails after pushing the tag, stop and report what exists (tag, release, assets, formula branch); don't delete a pushed tag or release without my say-so.

5. **Verify the formula.**
   After I say the formula PR is merged, run these and show the output:

   ```
   brew update
   brew upgrade enclave-ca
   brew test enclave-ca
   enclave-ca --version
   ```

   On a Mac without the tap, `brew tap micahhausler/enclave-ca https://github.com/micahhausler/enclave-ca` and `brew install enclave-ca` replace `brew upgrade`.
   Then remove the worktrees and local branches this release made.
