#!/usr/bin/env bash
# scan-repo:self-exempt
# ─────────────────────────────────────────────────────────────────────────────
# purge-repos.sh — plan & execute a connection-proof cleanup of the PolinRider
# payload across every branch of one or more GitHub repos, GitHub API only.
#
# The mass-poison adds ONE forged commit per branch on top of clean history
# (committer 'unknown' or a US-Pacific-forged timezone, ~the same minute).
# For each poisoned branch this resets the ref to the poison commit's first
# parent via a single PATCH — no clone, no pack transfer. If that parent is
# ALSO poisoned it walks back a few more; if nothing clean is found within
# $DEPTH the branch is flagged FILTER-REPO (rewrite by hand).
#
#   ./purge-repos.sh <owner> [repo ...]           # dry run — prints the plan
#   APPLY=1 ./purge-repos.sh <owner> [repo ...]   # execute the resets
#
# Requires: gh (authenticated: repo + workflow + read:org).
# ─────────────────────────────────────────────────────────────────────────────
set -u
APPLY="${APPLY:-0}"
DEPTH="${DEPTH:-8}"

OWNER="${1:-}"; shift || true
REPOS=("$@")
[ -z "$OWNER" ] && { echo "usage: $0 <owner> [repo ...]" >&2; exit 2; }
command -v gh >/dev/null || { echo "need gh" >&2; exit 2; }
gh auth status >/dev/null 2>&1 || { echo "gh not authenticated" >&2; exit 2; }

SIGS='_0x3d50aa|NONCE_FANOUT|BLOCK_MULTIPLE=0x3e8n|0xa322E5f39aDC2490Ef6f0121063eD311D3080e1a|/0x/(cl|ls)|/\$/boot|global\.i[[:space:]]*=[[:space:]]*.A8-|Cot%3t=shtP|rmcej%otb%'

# same spirit as scan-repo.sh: real carrier files only, and NOT inside
# vendor / node_modules / dist / build (stub configs there never execute).
excluded_path() {
  case "$1" in
    vendor/*|*/vendor/*|node_modules/*|*/node_modules/*|dist/*|*/dist/*|build/*|*/build/*|*.min.js) return 0 ;;
    *) return 1 ;;
  esac
}
is_carrier() {
  excluded_path "$1" && return 1
  case "$1" in
    *.config.js|*.config.mjs|*.config.cjs|*.config.ts|*.config.mts) return 0 ;;
    eslint.config.*|postcss.config.*|tailwind.config.*|vite.config.*|babel.config.*|metro.config.*|next.config.*) return 0 ;;
    */eslint.config.*|*/postcss.config.*|*/tailwind.config.*|*/vite.config.*|*/babel.config.*|*/metro.config.*|*/next.config.*) return 0 ;;
    *.woff2|*.woff|*.ttf|*.otf|*.eot) return 0 ;;
    .vscode/tasks.json|*/.vscode/tasks.json) return 0 ;;
    # NB: .gitignore attacker-litter (temp_*.bat / branch_structure.json) is
    # inert — it does not disqualify a reset target. The filter-repo callbacks
    # and the post-reset .gitignore sweep remove it.
    *) return 1 ;;
  esac
}

blob_bad() {
  local path="$1" b64="$2" dec
  dec=$(printf '%s' "$b64" | tr -d '\n' | base64 -d 2>/dev/null)
  case "$path" in
    *.woff2|*.woff|*.ttf|*.otf|*.eot)
      printf '%s' "$dec" | head -c4096 | LC_ALL=C grep -qE "$SIGS" && return 0
      local pr to
      pr=$(printf '%s' "$dec" | head -c4096 | LC_ALL=C tr -cd '[:print:][:space:]' | wc -c | tr -d ' ')
      to=$(printf '%s' "$dec" | head -c4096 | wc -c | tr -d ' ')
      [ "${to:-0}" -gt 200 ] && [ $((pr*100/to)) -ge 92 ] && \
        printf '%s' "$dec" | head -c4096 | grep -qE 'require\(|eval\(|child_process|_0x[0-9a-f]{4}|String\.fromCharCode|windowsHide' && return 0
      return 1 ;;
    *.vscode/tasks.json|.vscode/tasks.json|*/.vscode/tasks.json)
      printf '%s' "$dec" | grep -qE 'folderOpen|allowAutomaticTasks"?[[:space:]]*:[[:space:]]*true' && return 0
      return 1 ;;
    .gitignore|*/.gitignore)
      printf '%s' "$dec" | grep -qE 'temp_auto_push\.bat|temp_interactive_push\.bat|branch_structure\.json' && return 0
      return 1 ;;
    *)
      printf '%s' "$dec" | LC_ALL=C grep -qE "$SIGS" && return 0
      local mx; mx=$(printf '%s' "$dec" | awk '{if(length>m)m=length}END{print m+0}')
      [ "${mx:-0}" -gt 5000 ] && return 0
      return 1 ;;
  esac
}

commit_clean() {   # 0 = clean, 1 = poisoned
  local or="$1" csha="$2" tree path bsha b64
  tree=$(gh api "repos/$or/commits/$csha" --jq '.commit.tree.sha' 2>/dev/null) || return 1
  [ -z "$tree" ] && return 1
  while IFS=$'\t' read -r path bsha; do
    [ -z "$path" ] && continue
    is_carrier "$path" || continue
    b64=$(gh api "repos/$or/git/blobs/$bsha" --jq '.content' 2>/dev/null)
    [ -z "$b64" ] && continue
    blob_bad "$path" "$b64" && { LASTBAD="$path"; return 1; }
  done < <(gh api "repos/$or/git/trees/$tree?recursive=1" \
           --jq '.tree[] | select(.type=="blob") | "\(.path)\t\(.sha)"' 2>/dev/null)
  return 0
}

if [ "${#REPOS[@]}" -eq 0 ]; then
  REPOS=()
  while IFS= read -r n; do [ -n "$n" ] && REPOS+=("$n"); done \
    < <(gh api "orgs/$OWNER/repos" --paginate --jq '.[].name' 2>/dev/null)
  if [ "${#REPOS[@]}" -eq 0 ] && [ "$OWNER" = "$(gh api user --jq .login 2>/dev/null)" ]; then
    while IFS= read -r n; do [ -n "$n" ] && REPOS+=("$n"); done \
      < <(gh api "user/repos?affiliation=owner&per_page=100" --paginate --jq '.[].name' 2>/dev/null)
  fi
  [ "${#REPOS[@]}" -eq 0 ] && while IFS= read -r n; do [ -n "$n" ] && REPOS+=("$n"); done \
    < <(gh api "users/$OWNER/repos" --paginate --jq '.[].name' 2>/dev/null)
  [ "${#REPOS[@]}" -eq 0 ] && { echo "no repos for $OWNER" >&2; exit 1; }
fi

echo "### $([ "$APPLY" = 1 ] && echo EXECUTE || echo 'DRY RUN') — $OWNER — ${#REPOS[@]} repos — $(date -u +%FT%TZ)"
echo
C=0; R=0; F=0

for repo in "${REPOS[@]}"; do
  or="$OWNER/$repo"
  branches=$(gh api "repos/$or/branches" --paginate --jq '.[].name' 2>/dev/null)
  [ -z "$branches" ] && continue
  hdr=0
  while IFS= read -r br; do
    [ -z "$br" ] && continue
    tip=$(gh api "repos/$or/branches/$br" --jq '.commit.sha' 2>/dev/null)
    [ -z "$tip" ] && continue

    LASTBAD=""
    if commit_clean "$or" "$tip"; then C=$((C+1)); continue; fi

    [ "$hdr" = 0 ] && { echo "── $or ──"; hdr=1; }
    tipmeta=$(gh api "repos/$or/commits/$tip" --jq '"\(.commit.committer.name) \(.commit.committer.date)"' 2>/dev/null)

    # walk: poison tip, then its parent chain, until a clean commit
    chain=$(gh api "repos/$or/commits?sha=$tip&per_page=$DEPTH" --jq '.[].sha' 2>/dev/null)
    target=""; steps=0
    while IFS= read -r c; do
      [ -z "$c" ] && continue
      [ "$c" = "$tip" ] && continue
      steps=$((steps+1))
      if commit_clean "$or" "$c"; then target="$c"; break; fi
    done <<< "$chain"

    parents=$(gh api "repos/$or/commits/$tip" --jq '.parents | length' 2>/dev/null)
    if [ -z "$target" ]; then
      if [ "${parents:-0}" -eq 0 ]; then
        echo "   $br : born-poisoned root ($LASTBAD)  ->  FILTER-REPO / rebuild"
      else
        echo "   $br : no clean commit in last $DEPTH ($LASTBAD)  ->  FILTER-REPO"
      fi
      F=$((F+1)); continue
    fi
    msg=$(gh api "repos/$or/commits/$target" --jq '.commit.message' 2>/dev/null | head -1)
    tmeta=$(gh api "repos/$or/commits/$target" --jq '"\(.commit.committer.name) \(.commit.committer.date)"' 2>/dev/null)
    echo "   $br : reset $(echo "$tip"|cut -c1-9) -> $(echo "$target"|cut -c1-9)  (back $steps)"
    echo "        poisoned tip : [$tipmeta]"
    echo "        reset target : [$tmeta]  $msg"
    R=$((R+1))
    if [ "$APPLY" = 1 ]; then
      if gh api --method PATCH "repos/$or/git/refs/heads/$br" -f sha="$target" -F force=true >/dev/null 2>&1; then
        echo "        ✓ reset"
      else
        echo "        ✗ PATCH failed"
      fi
    fi
  done <<< "$branches"
done

echo
echo "### clean: $C   reset: $R   filter-repo: $F"
[ "$APPLY" != 1 ] && echo "### dry run — re-run with APPLY=1 to execute"
