#!/usr/bin/env bash
# The Dockerfile's build context from the committed tree, in DIR: this
# package at the root. In the public repo that's all (Cargo.toml takes vlsync
# and vlatproto as git dependencies). In the monorepo they sit beside this
# package as path dependencies, so they're added under deps/, the manifest's
# paths are pointed there and the context's Dockerfile copies deps/.
#
#   build/context.sh DIR
set -euo pipefail
out=$1
cd "$(dirname "$0")/.."
parent=..
if [ -f "$parent/../scripts/vcs.sh" ]; then
  . "$parent/../scripts/vcs.sh"
else
  # the public repo: a git clone, without mono's scripts/
  vcs_root() { git rev-parse --show-toplevel; }
  vcs_prefix() { git rev-parse --show-prefix; }
  vcs_archive() { if [ "$1" = -C ]; then git -C "$2" archive "${@:3}"; else git archive "$@"; fi; }
fi
top=$(vcs_root)
prefix=$(vcs_prefix)
# from the top: in a subdirectory, an archive narrows the tree to it again
vcs_archive -C "$top" "HEAD:$prefix" | tar -x -C "$out"
if grep -q "path = \"$parent/vlsync/" "$out/Cargo.toml"; then
  for dep in vlsync vlatproto; do
    mkdir -p "$out/deps/$dep"
    vcs_archive -C "$top" "HEAD:$(dirname "$prefix")/$dep" | tar -x -C "$out/deps/$dep"
  done
  perl -pi -e "s#path = \"\Q$parent\E/(vlsync/|vlatproto\")#path = \"deps/\$1#" "$out/Cargo.toml"
  perl -pi -e 's#^COPY Cargo.toml Cargo.lock ./$#$&\nCOPY deps ./deps#' "$out/Dockerfile"
  grep -q '^COPY deps ./deps$' "$out/Dockerfile" || { echo "context: no COPY of deps/ in the Dockerfile" >&2; exit 1; }
fi
[ -f "$out/Dockerfile" ] && ! grep -q "path = \"$parent/" "$out/Cargo.toml" || { echo "context: incomplete build context in $out" >&2; exit 1; }
