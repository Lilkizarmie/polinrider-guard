#!/usr/bin/env bash
# scan-repo:self-exempt
# ─────────────────────────────────────────────────────────────────────────────
# audit-repos.sh — READ-ONLY remote scan for the "PolinRider" RAT-stager
# across every branch of one or more GitHub repos, using the GitHub API only.
#
# Why the API instead of `git clone`: it needs no local disk, no pack
# transfer, and no working copy — so it works even on a bad connection, and
# it can NEVER modify, force-push, or delete anything. It only reads.
#
# Usage:
#   ./audit-repos.sh <owner>                       scan every repo the token can see for <owner>
#   ./audit-repos.sh <owner> <repo> [<repo> ...]    scan specific repos
#
# Requires: `gh` CLI, already authenticated (`gh auth status`) with read
# access to the repos in question.
#
# This script never writes to GitHub. It only prints a report. Cleaning up
# what it finds is a separate, human-reviewed step — see PURGE-PLAYBOOK.md.
# ─────────────────────────────────────────────────────────────────────────────
set -u

OWNER="${1:-}"
shift || true
REPOS=("$@")

if [ -z "$OWNER" ]; then
  echo "usage: $0 <owner> [repo ...]" >&2
  exit 2
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "error: the GitHub CLI ('gh') is required. Install: https://cli.github.com/" >&2
  exit 2
fi
if ! gh auth status >/dev/null 2>&1; then
  echo "error: gh is not authenticated. Run: gh auth login" >&2
  exit 2
fi

# Same signature set as githooks/scan-repo.sh — keep these in sync.
SIGS='_0x3d50aa|NONCE_FANOUT|BLOCK_MULTIPLE=0x3e8n|0xa322E5f39aDC2490Ef6f0121063eD311D3080e1a|/0x/(cl|ls)|/\$/boot|global\.i[[:space:]]*=[[:space:]]*.A8-|Cot%3t=shtP|rmcej%otb%'

# Only these paths are worth fetching blob content for — this is the entire
# observed carrier set (build configs the attacker poisons, plus fake fonts
# and the hidden auto-run task file). Bounds the number of API calls per repo.
is_carrier_path() {
  case "$1" in
    *.config.js|*.config.mjs|*.config.cjs|*.config.ts) return 0 ;;
    eslint.config.*|postcss.config.*|tailwind.config.*|vite.config.*|babel.config.*) return 0 ;;
    *.woff2|*.woff|*.ttf|*.otf|*.eot) return 0 ;;
    .vscode/tasks.json) return 0 ;;
    *) return 1 ;;
  esac
}

TOTAL_REPOS=0
TOTAL_POISONED=0
declare -a POISONED_SUMMARY=()

scan_blob() {
  # $1 = owner/repo  $2 = blob sha  $3 = path (for reporting)
  local or="$1" sha="$2" path="$3"
  local b64
  b64=$(gh api "repos/$or/git/blobs/$sha" --jq '.content' 2>/dev/null) || return 1
  [ -z "$b64" ] && return 1

  # font/otf/ttf/etc: check magic bytes instead of grepping (they're binary)
  case "$path" in
    *.woff2|*.woff|*.ttf|*.otf|*.eot)
      local magic
      magic=$(printf '%s' "$b64" | tr -d '\n' | base64 -d 2>/dev/null | head -c4 | od -An -tx1 | tr -d ' \n')
      case "$magic" in
        774f4632|774f4646|4f54544f|00010000|74727565|74746366) return 1 ;;  # legit font
        *) echo "    fake font (wrong magic bytes ${magic:-empty}): $path"; return 0 ;;
      esac
      ;;
    .vscode/tasks.json)
      if printf '%s' "$b64" | tr -d '\n' | base64 -d 2>/dev/null | grep -qE 'folderOpen|allowAutomaticTasks"?[[:space:]]*:[[:space:]]*true'; then
        echo "    hidden auto-run task: $path"; return 0
      fi
      return 1
      ;;
    *)
      local decoded
      decoded=$(printf '%s' "$b64" | tr -d '\n' | base64 -d 2>/dev/null)
      if printf '%s' "$decoded" | grep -qE "$SIGS"; then
        echo "    payload signature match: $path"; return 0
      fi
      local maxlen
      maxlen=$(printf '%s' "$decoded" | awk '{ if (length > m) m = length } END { print m+0 }')
      if [ "${maxlen:-0}" -gt 5000 ]; then
        echo "    long-line config (${maxlen} chars on one line — tab-wall trick): $path"; return 0
      fi
      return 1
      ;;
  esac
}

scan_branch() {
  local or="$1" branch="$2"
  local tree_sha hit_count=0
  tree_sha=$(gh api "repos/$or/branches/$branch" --jq '.commit.commit.tree.sha' 2>/dev/null) || return
  [ -z "$tree_sha" ] && return

  local entries
  entries=$(gh api "repos/$or/git/trees/$tree_sha?recursive=1" --jq '.tree[] | select(.type=="blob") | "\(.path)\t\(.sha)"' 2>/dev/null)
  [ -z "$entries" ] && return

  local branch_hits=""
  while IFS=$'\t' read -r path sha; do
    [ -z "$path" ] && continue
    is_carrier_path "$path" || continue
    local out
    out=$(scan_blob "$or" "$sha" "$path")
    [ -n "$out" ] && branch_hits+="$out"$'\n'
  done <<< "$entries"

  if [ -n "$branch_hits" ]; then
    echo "  branch $branch: POISONED"
    printf '%s' "$branch_hits"
    hit_count=1
  fi
  return $((1 - hit_count))
}

scan_repo() {
  local repo="$1" or="$OWNER/$1"
  TOTAL_REPOS=$((TOTAL_REPOS + 1))
  echo "── $or ──"

  local branches
  branches=$(gh api "repos/$or/branches" --paginate --jq '.[].name' 2>/dev/null)
  if [ -z "$branches" ]; then
    echo "  (no branches found / no access — skipping)"
    return
  fi

  local repo_poisoned=0
  while IFS= read -r b; do
    [ -z "$b" ] && continue
    if scan_branch "$or" "$b"; then
      repo_poisoned=1
    fi
  done <<< "$branches"

  if [ "$repo_poisoned" -eq 1 ]; then
    TOTAL_POISONED=$((TOTAL_POISONED + 1))
    POISONED_SUMMARY+=("$or")
  else
    echo "  clean (all branches)"
  fi
  echo
}

if [ "${#REPOS[@]}" -eq 0 ]; then
  echo "No repo list given — fetching every repo for '$OWNER'..."
  mapfile -t REPOS < <(gh api "orgs/$OWNER/repos" --paginate --jq '.[].name' 2>/dev/null)
  if [ "${#REPOS[@]}" -eq 0 ]; then
    mapfile -t REPOS < <(gh api "users/$OWNER/repos" --paginate --jq '.[].name' 2>/dev/null)
  fi
  if [ "${#REPOS[@]}" -eq 0 ]; then
    echo "error: couldn't list repos for '$OWNER' (bad name, or no access)." >&2
    exit 1
  fi
  echo "Found ${#REPOS[@]} repo(s): ${REPOS[*]}"
  echo
fi

for r in "${REPOS[@]}"; do
  scan_repo "$r"
done

echo "═══════════════════════════════════════════"
echo "Scanned: $TOTAL_REPOS repo(s)   Poisoned: $TOTAL_POISONED"
if [ "$TOTAL_POISONED" -gt 0 ]; then
  echo
  echo "Poisoned repos:"
  for p in "${POISONED_SUMMARY[@]}"; do echo "  - $p"; done
  echo
  echo "This was a READ-ONLY scan — nothing was changed. For remediation steps"
  echo "(git-filter-repo callbacks, or a connection-proof GitHub-API-only purge),"
  echo "see PURGE-PLAYBOOK.md in this toolkit. Review every step before running it —"
  echo "purging rewrites history and needs a human to pick the right clean commit."
fi
