# sourced by each hook: run any repo-local hook of the same name, then husky's.
# (a global core.hooksPath disables .git/hooks, so we re-invoke them explicitly)
_chain() {
  name="$1"; shift
  self_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  # --git-dir ignores core.hooksPath, so this is the REAL per-repo hooks dir
  gitdir="$(git rev-parse --git-dir 2>/dev/null || true)"
  top="$(git rev-parse --show-toplevel 2>/dev/null || true)"
  # also honour a repo's own checked-in hook (some teams' postinstall installs
  # one at scripts/hooks/<name> — this makes sure it still runs too)
  for cand in "${gitdir:+$gitdir/hooks/$name}" "${top:+$top/.husky/$name}" \
              "${top:+$top/scripts/hooks/$name}"; do
    [ -n "$cand" ] && [ -x "$cand" ] || continue
    case "$cand" in "$self_dir"/*) continue ;; esac   # never call ourselves
    "$cand" "$@" || return $?
  done
}
