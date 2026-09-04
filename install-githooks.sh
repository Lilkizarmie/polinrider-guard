#!/usr/bin/env bash
# Point every git repo on this Mac at the shared malware-scanning hooks.
#
#   reference-transaction : block a fetch/pull that would bring in the payload
#   post-merge            : roll back a `git pull` that landed the payload
#   post-checkout         : warn after a checkout that put the payload on disk
#   post-rewrite          : warn after a rebase/amend that surfaced the payload
#   pre-commit / pre-push : block committing or pushing the payload
#
# A repo's own hooks (incl. husky) still run — the shared hooks chain to them.
#
# The hook files are set user-immutable (chflags uchg) after install. Some
# projects' own `postinstall` scripts try to overwrite the repo-local hooks
# directory (e.g. a `scripts/hooks/install.js` that copies files into
# core.hooksPath) — uchg makes that fail closed (EPERM) instead of silently
# replacing the scanner. To edit a hook yourself:
#   chflags nouchg githooks/*   &&   <edit>   &&   bash install-githooks.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOKS="$HERE/githooks"

HOOK_FILES=(scan-repo.sh _chain.sh post-merge post-checkout post-rewrite
            pre-commit pre-push reference-transaction)

chflags nouchg "${HOOK_FILES[@]/#/$HOOKS/}" 2>/dev/null || true
chmod +x "${HOOK_FILES[@]/#/$HOOKS/}"

git config --global core.hooksPath "$HOOKS"
echo "✓ global core.hooksPath -> $HOOKS"
echo "  (every repo you clone/fetch/pull from now on is scanned automatically)"
echo

echo "One-time scan of existing repos (edit the SCAN_DIRS list below to match"
echo "where your repos actually live — this is just a common default):"
SCAN_DIRS=("$HOME"/Documents/GitHub/*/ "$HOME"/Documents/Github/*/ "$HOME"/dev/*/ "$HOME"/code/*/ "$HOME"/repos/*/)
for d in "${SCAN_DIRS[@]}"; do
  d="${d%/}"
  [ -d "$d/.git" ] || continue
  printf '  %-45s ' "$(basename "$d")"
  if "$HOOKS/scan-repo.sh" "$d" 2>/dev/null; then echo "clean"; else echo "SEE WARNING ABOVE"; fi
done

chflags uchg "${HOOK_FILES[@]/#/$HOOKS/}" 2>/dev/null || true
echo
echo "hook files locked (chflags uchg) — a rogue postinstall can't overwrite them."
echo "Undo:  chflags nouchg $HOOKS/* ; git config --global --unset core.hooksPath"
