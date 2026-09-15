#!/usr/bin/env bash
# Recompute flake.nix's vendorHash and rewrite it in place.
#
# buildGoModule fetches the module set in a fixed-output derivation, so the
# hash is a function of go.sum. Any dependency change moves it, and `nix build`
# then fails with a mismatch. Dependabot cannot update flake.nix, so without
# this every bump needs the hash copied out of an error message by hand.
#
# Exits 0 and prints nothing when the hash is already correct, so it is safe to
# run unconditionally and to test with `git diff --exit-code flake.nix`.
set -euo pipefail

flake="${1:-flake.nix}"

if ! command -v nix >/dev/null 2>&1; then
  echo "update-vendor-hash: nix is not installed" >&2
  exit 127
fi

# A build against a deliberately wrong hash makes nix report the real one.
# Substituting a known-bad value is more reliable than parsing a build that
# might succeed: if the current hash happens to be correct the build succeeds
# and prints no "got:" line at all.
fake="sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
current="$(sed -n 's/.*vendorHash = "\(sha256-[^"]*\)".*/\1/p' "$flake" | head -1)"

if [ -z "$current" ]; then
  echo "update-vendor-hash: no vendorHash found in $flake" >&2
  exit 1
fi

restore() { sed -i.bak "s|vendorHash = \"$fake\"|vendorHash = \"$current\"|" "$flake" && rm -f "$flake.bak"; }
trap restore EXIT

sed -i.bak "s|vendorHash = \"$current\"|vendorHash = \"$fake\"|" "$flake" && rm -f "$flake.bak"

# The build is expected to fail; the hash is in the error.
log="$(nix build .#rapg --no-link 2>&1 || true)"
actual="$(printf '%s\n' "$log" | sed -n 's/.*got: *\(sha256-[A-Za-z0-9+/=]*\).*/\1/p' | head -1)"

trap - EXIT
restore

if [ -z "$actual" ]; then
  echo "update-vendor-hash: could not read a hash from the build output" >&2
  printf '%s\n' "$log" >&2
  exit 1
fi

if [ "$actual" = "$current" ]; then
  exit 0
fi

sed -i.bak "s|vendorHash = \"$current\"|vendorHash = \"$actual\"|" "$flake" && rm -f "$flake.bak"
echo "update-vendor-hash: $current -> $actual"
