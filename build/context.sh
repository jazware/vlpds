#!/usr/bin/env bash
# The Dockerfile's build context from the committed tree, in DIR: this
# package at the root and the vlsync crates it builds from in vlsync/ (the
# public repo's layout). In the monorepo those crates live beside this
# package, so they're added and the manifest's path dependencies are pointed
# into DIR.
#
#   build/context.sh DIR
set -euo pipefail
out=$1
cd "$(dirname "$0")/.."
parent=..
if [ -f "$parent/../scripts/vcs.sh" ]; then
  . "$parent/../scripts/vcs.sh"
else
  vcs_root() { git rev-parse --show-toplevel; }
  vcs_prefix() { git rev-parse --show-prefix; }
  vcs_archive() { if [ "$1" = -C ]; then git -C "$2" archive "${@:3}"; else git archive "$@"; fi; }
fi
top=$(vcs_root)
prefix=$(vcs_prefix)
# from the top: in a subdirectory, an archive narrows the tree to it again
vcs_archive -C "$top" "HEAD:$prefix" | tar -x -C "$out"
if [ ! -d vlsync ] && [ -d "$parent/vlsync" ]; then
  mkdir -p "$out/vlsync"
  vcs_archive -C "$top" "HEAD:$(dirname "$prefix")/vlsync" | tar -x -C "$out/vlsync"
  sed -i.orig "s#path = \"$parent/vlsync/#path = \"vlsync/#" "$out/Cargo.toml"
  rm "$out/Cargo.toml.orig"
fi
[ -f "$out/Dockerfile" ] && [ -f "$out/vlsync/Cargo.toml" ] || { echo "context: incomplete build context in $out" >&2; exit 1; }
