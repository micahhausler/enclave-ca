#!/usr/bin/env bash
# Tag and publish a source-only enclave-ca release from a Mac.
#
#   scripts/release.sh --dry-run 0.2.0   # test and package into dist/0.2.0; publish nothing
#   scripts/release.sh 0.2.0             # also push tag v0.2.0, create the GitHub release, and open the formula PR
#
# Sources/EnclaveCA/Version.swift must already say the version, merged to main.
set -Eeuo pipefail

die() { echo "release: $*" >&2; exit 1; }
log() { echo "release: $*" >&2; }
trap 'echo "release: failed at line $LINENO: $BASH_COMMAND" >&2' ERR

dry=false
if [[ ${1:-} == --dry-run ]]; then dry=true; shift; fi
[[ $# -eq 1 ]] || die "usage: scripts/release.sh [--dry-run] VERSION"
version=$1
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "VERSION must look like 1.2.3, got \"$version\""

tag=v$version
repo=micahhausler/enclave-ca
src_name=enclave-ca-$version
out=dist/$version
src_url=https://github.com/$repo/releases/download/$tag/$src_name.tar.gz
src_sha=
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

# A dry run warns where a release would stop, so it can run from a branch.
check() { if $dry; then log "warning: $*"; else die "$*"; fi; }

tag_exists() {
  git rev-parse -q --verify "refs/tags/$tag" >/dev/null ||
    [[ -n $(git ls-remote --tags origin "refs/tags/$tag") ]]
}

preflight() {
  for c in swift git gh gh-bot shasum; do
    command -v "$c" >/dev/null || die "$c isn't on PATH"
  done
  [[ $(uname -s) == Darwin ]] || die "run this on a Mac"

  git fetch -q origin main --tags
  [[ $(git rev-parse --abbrev-ref HEAD) == main ]] || check "HEAD isn't main"
  git diff --quiet HEAD || check "tracked files have uncommitted changes"
  [[ $(git rev-parse HEAD) == $(git rev-parse origin/main) ]] || check "HEAD isn't origin/main"
  if tag_exists; then check "tag $tag already exists"; fi
  grep -qx "public let enclaveCAVersion = \"$version\"" Sources/EnclaveCA/Version.swift ||
    die "Sources/EnclaveCA/Version.swift doesn't say $version; bump it in a PR first"
}

package() {
  log "testing"
  swift test

  rm -rf "$out"
  mkdir -p "$out"
  git archive --format=tar.gz --prefix="$src_name/" -o "$out/$src_name.tar.gz" HEAD
  src_sha=$(shasum -a 256 "$out/$src_name.tar.gz" | cut -d' ' -f1)
  echo "$src_sha  $src_name.tar.gz" >"$out/SHA256SUMS"

  # Build the tarball the way Homebrew does.
  log "building from the source tarball"
  tar -C "$stage" -xzf "$out/$src_name.tar.gz"
  swift build -c release --disable-sandbox --package-path "$stage/$src_name"
  local built
  built=$("$stage/$src_name/.build/release/enclave-ca" --version)
  [[ $built == "enclave-ca $version" ]] || die "the source tarball builds \"$built\", not enclave-ca $version"

  cat "$out/SHA256SUMS"
}

publish() {
  log "tagging and publishing $tag"
  git tag -a "$tag" -m "enclave-ca $version"
  git push origin "$tag"
  gh release create "$tag" --repo "$repo" --verify-tag --title "enclave-ca $version" --generate-notes \
    "$out/$src_name.tar.gz" "$out/SHA256SUMS"

  local got
  got=$(gh release download "$tag" --repo "$repo" --pattern "$src_name.tar.gz" --output - | shasum -a 256 | cut -d' ' -f1)
  [[ $got == "$src_sha" ]] || die "the uploaded $src_name.tar.gz has sha256 $got, expected $src_sha"
}

open_formula_pr() {
  log "opening the formula PR"
  local branch=formula-$tag
  local wt=.worktree/$branch
  local title="enclave-ca: Homebrew formula builds $version"

  git worktree add -q -b "$branch" "$wt" origin/main
  sed -i '' \
    -e "s|^  url \".*\"|  url \"$src_url\"|" \
    -e "s|^  sha256 \".*\"|  sha256 \"$src_sha\"|" \
    "$wt/Formula/enclave-ca.rb"
  git -C "$wt" commit -q -am "$title"
  git -C "$wt" push -q -u origin "$branch"
  (cd "$wt" && gh-bot pr create --reviewer micahhausler --base main --head "$branch" --title "$title" \
    --body "\`Formula/enclave-ca.rb\` builds $tag from the release's source tarball.")
  git worktree remove "$wt"
}

cd "$(git rev-parse --show-toplevel)"
preflight
package
if $dry; then
  log "dry run: packaged $out; nothing tagged or published"
  exit 0
fi
publish
open_formula_pr
log "released $tag: https://github.com/$repo/releases/tag/$tag"
