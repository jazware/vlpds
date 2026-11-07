#!/usr/bin/env bash
# Builds the vlpds under test (--profile dev-release) and prints the binary's
# path as the last line on stdout. By default that's this checkout's
# packages/vlpds as it is on disk, uncommitted changes included; BRANCH=<ref>
# builds a detached checkout of that ref under .scratch/vlpds-src instead.
# Skips the build when the source is clean and hasn't changed since the last.
#
#   bench/spaces/build-vlpds.sh        (BRANCH=origin/some-branch pins a ref)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
scratch="$here/.scratch"
mkdir -p "$scratch"
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

# A delta (jj) checkout has no git: build this checkout as it is on disk,
# every time (cargo's incremental build makes an unchanged tree cheap).
if ! git -C "$here" rev-parse --git-dir >/dev/null 2>&1; then
  [ -z "${BRANCH:-}" ] || { echo "BRANCH needs a git checkout; in a delta checkout, check the ref out (dj new <ref>) or pass VLPDS_BIN" >&2; exit 2; }
  target="${VLPDS_TARGET_DIR:-$scratch/target}"
  src="$(cd "$here/../.." && pwd)"
  rev="$(jj -R "$src" log -r @ --no-graph -T commit_id 2>/dev/null || echo unknown)"
  echo "building vlpds @ ${rev:0:12} from $src into $target" >&2
  cd "$src"
  (cd ui && npm install --no-audit --no-fund --silent && npm run build --silent) >&2
  CARGO_TARGET_DIR="$target" nice cargo build --profile dev-release --bin vlpds >&2
  cp "$target/dev-release/vlpds" "$scratch/vlpds"
  echo "@" >"$scratch/built-branch"
  echo "$rev" >"$scratch/built-rev"
  rm -f "$scratch/built-key"
  echo "$scratch/vlpds"
  exit 0
fi

# One target dir for every checkout of the repo (the main one's), so a
# worktree's first run reuses its compiled dependencies.
common="$(git -C "$here" rev-parse --path-format=absolute --git-common-dir)"
if [ "$(basename "$common")" = .git ]; then
  target="${VLPDS_TARGET_DIR:-$(dirname "$common")/packages/vlpds/bench/spaces/.scratch/target}"
else
  target="${VLPDS_TARGET_DIR:-$scratch/target}"
fi

if [ -n "${BRANCH:-}" ]; then
  case "$BRANCH" in origin/*) git -C "$here" fetch -q origin || echo "fetch failed; using local refs" >&2 ;; esac
  rev="$(git -C "$here" rev-parse "$BRANCH^{commit}")"
  src="$scratch/vlpds-src"
  if [ ! -d "$src" ]; then
    git -C "$here" worktree add -q --detach "$src" "$rev"
  else
    git -C "$src" checkout -q --detach "$rev"
  fi
  label="$BRANCH" dirty=""
  key="$src $rev"
  src="$src/packages/vlpds"
else
  src="$(cd "$here/../.." && pwd)"
  rev="$(git -C "$src" rev-parse HEAD)"
  label=HEAD
  # bench/ isn't in the binary, and the harness itself lives there
  dirty="$(git -C "$src" status --porcelain -- . ':!bench' | head -1)"
  [ -n "$dirty" ] && label="HEAD+dirty"
  key="$src $(git -C "$src" ls-tree --full-tree HEAD:./ | grep -v "	bench$" | git hash-object --stdin)"
fi

# A copy per checkout: another checkout's build replaces the target dir's
# binary, and a driver may restart vlpds from this path mid-run.
bin="$scratch/vlpds"
if [ -z "$dirty" ] && [ -x "$bin" ] && [ "$(cat "$scratch/built-key" 2>/dev/null)" = "$key" ]; then
  echo "vlpds $label ${rev:0:12} already built" >&2
  echo "$bin"
  exit 0
fi
echo "building vlpds $label ${rev:0:12} from $src into $target" >&2
cd "$src"
(cd ui && npm install --no-audit --no-fund --silent && npm run build --silent) >&2
CARGO_TARGET_DIR="$target" nice cargo build --profile dev-release --bin vlpds >&2
rm -f "$bin"
cp -c "$target/dev-release/vlpds" "$bin" 2>/dev/null || cp "$target/dev-release/vlpds" "$bin"
echo "$label" >"$scratch/built-branch"
echo "$rev" >"$scratch/built-rev"
echo "$key" >"$scratch/built-key"
echo "$bin"
