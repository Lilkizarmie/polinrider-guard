#!/usr/bin/env bash
# scan-repo:self-exempt
# ─────────────────────────────────────────────────────────────────────────────
# scan-repo.sh — detect the "PolinRider" RAT-stager payload in a git repo.
#
# Checks the working tree AND every local + remote-tracking branch tip, so a
# `git fetch` that pulls a poisoned branch is caught even before checkout.
#
#   scan-repo.sh            warn only, exit 0   (post-merge / post-checkout)
#   scan-repo.sh --block    exit 1 on a hit     (pre-commit / pre-push)
#
# Signatures + incident writeup: ../README.md (this toolkit's root)
# ─────────────────────────────────────────────────────────────────────────────
set -u

BLOCK=0
WORKTREE_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --block)    BLOCK=1; shift ;;
    --worktree) WORKTREE_ONLY=1; shift ;;   # skip the branch-tip scan (post-merge revert decision)
    *) break ;;
  esac
done

ROOT="${1:-$(git rev-parse --show-toplevel 2>/dev/null || true)}"
[ -z "$ROOT" ] && exit 0
cd "$ROOT" 2>/dev/null || exit 0

# obfuscated-blob markers (multiple observed variants) · on-chain C2 paths ·
# known attacker wallet · campaign version tags
SIGS='_0x3d50aa|NONCE_FANOUT|BLOCK_MULTIPLE=0x3e8n|0xa322E5f39aDC2490Ef6f0121063eD311D3080e1a|/0x/(cl|ls)|/\$/boot|global\.i[[:space:]]*=[[:space:]]*.A8-|Cot%3t=shtP|rmcej%otb%'
EXCLUDE=(
  ':!vendor' ':!node_modules' ':!*.min.js' ':!*.min.css' ':!dist' ':!build'
  # security tooling that carries these strings *as detection patterns*
  ':!**/scan-repo.sh' ':!**/malware-guard.sh' ':!**/block-c2-hosts.sh'
  ':!**/reference-transaction' ':!**/purge-callbacks/**' ':!**/audit-repos.sh'
  ':!**/check-config-integrity.js' ':!**/check-forged-merges.sh'
  ':!**/audit-lifecycle-scripts.js' ':!**/known-bad-iocs.txt'
  ':!**/known-forged-merges.txt' ':!**/security/README.md' ':!security/**'
  # a team's own incident-response scripts (e.g. scripts/ci + scripts/hooks)
  ':!**/purge-incident-history.sh' ':!scripts/ci/**' ':!scripts/hooks/**'
  ':!**/SECURITY*.md' ':!**/INCIDENT*.md'
)

# drop any hit whose file self-declares as scanner tooling, OR reads like an
# incident-response / purge script (contains the IOCs *as patterns to remove*).
_filter_self() {
  local body
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    body=$(cat "$f" 2>/dev/null || git show "HEAD:$f" 2>/dev/null)
    printf '%s' "$body" | grep -q 'scan-repo:self-exempt' && continue
    # a defensive script: shebang + filter-repo/purge language, and NO runtime
    # payload behaviour (no eval/spawn/child_process/atob against these strings)
    if printf '%s' "$body" | grep -qE 'git.?filter.?repo|Incident History Purge|INVERT_PATHS|--strip-blobs|BLOB_CALLBACK' \
       && ! printf '%s' "$body" | grep -qE 'child_process|require\(.child_process|spawn\(|\beval\(|windowsHide|eth_getBlockByNumber|String\.fromCharCode|atob\('; then
      continue
    fi
    printf '%s\n' "$f"
  done
}

hits=""

# 1 — tracked files, working tree
w=$(git grep -lIE "$SIGS" -- "${EXCLUDE[@]}" 2>/dev/null | _filter_self || true)
[ -n "$w" ] && hits+="  working tree:      $(echo "$w" | tr '\n' ' ')"$'\n'

# 2 — every branch tip we have a ref for (local + fetched remotes)
if [ "$WORKTREE_ONLY" -eq 0 ]; then
while IFS= read -r ref; do
  [ -z "$ref" ] && continue
  r=$(git grep -lIE "$SIGS" "$ref" -- "${EXCLUDE[@]}" 2>/dev/null | sed "s#^${ref}:##" | _filter_self | tr '\n' ' ' || true)
  [ -n "$r" ] && hits+="  ${ref}:  ${r}"$'\n'
done < <(git for-each-ref --format='%(refname)' refs/heads refs/remotes 2>/dev/null)
fi

# 3 — the tab-wall trick: an absurd line length in a build config
while IFS= read -r f; do
  [ -f "$f" ] || continue
  L=$(awk '{ if (length > m) m = length } END { print m+0 }' "$f")
  [ "${L:-0}" -gt 5000 ] && hits+="  long-line config:  $f (${L} chars on one line)"$'\n'
done < <(git ls-files -- '*.config.js' '*.config.mjs' '*.config.cjs' '*.config.ts' \
                          'eslint.config.*' 'postcss.config.*' 'tailwind.config.*' 'vite.config.*' 2>/dev/null)

# 4 — a "font" that is actually text/JS (wrong magic bytes)
while IFS= read -r f; do
  [ -f "$f" ] || continue
  m=$(head -c4 "$f" 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n')
  case "$m" in
    774f4632|774f4646|4f54544f|0001000*|74727565|74746366) ;;   # wOF2 wOFF OTTO ttf true ttcf
    *) hits+="  fake font:         $f (first bytes ${m:-empty})"$'\n' ;;
  esac
done < <(git ls-files -- '*.woff2' '*.woff' '*.ttf' '*.otf' '*.eot' 2>/dev/null)

# 5 — hidden editor auto-run
a=$(git grep -lIE 'folderOpen|allowAutomaticTasks"?[[:space:]]*:[[:space:]]*true' -- '.vscode/*' 2>/dev/null || true)
[ -n "$a" ] && hits+="  .vscode auto-run:  $(echo "$a" | tr '\n' ' ')"$'\n'

[ -z "$hits" ] && exit 0

{
  echo
  echo "malware-scan: RAT-stager injection in $(basename "$ROOT")"
  printf '%s' "$hits"
  echo
  echo "    Obfuscated Ethereum-C2 / XOR-eval / detached-node payload."
  echo "    Do NOT build, lint, run, or open in an editor with extensions."
  echo "    Reset to a known-good commit - see PURGE-PLAYBOOK.md in this toolkit"
  echo
} >&2

if [ "$BLOCK" -eq 1 ]; then
  echo "    blocked. (git --no-verify overrides, only if you are sure it's a false positive.)" >&2
  exit 1
fi
echo "    (warning only - this ran after the pull/checkout.)" >&2
exit 0
