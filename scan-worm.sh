#!/usr/bin/env bash
# scan-repo:self-exempt
#
# Void Dokkaebi / PolinRider indicator scan — LOCAL FILESYSTEM sweep.
#
# Contributed by a collaborator on the incident response; kept close to the
# original. Complements the other scanners here:
#   scan-repo.sh    — one git repo, working tree + every branch tip
#   audit-repos.sh  — remote scan of a whole GitHub owner/org (no clone)
#   scan-worm.sh    — this: walk a whole directory tree of local clones at once
#
# Read-only: only runs find / grep / awk / git config --get / git remote -v.
# Nothing it finds is executed; nothing is downloaded, modified, or sent out.
#
# Usage:  bash scan-worm.sh [directory]     (defaults to the current dir)
#
# Steps 3 and 8 will flag minified vendor JS/CSS and RN bundles. A real hit is
# an obfuscator blob AFTER a wall of padding; a normal minified library on one
# long line is not. Eyeball before acting.
set -uo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

ROOT="${1:-.}"
FINDINGS=0
REVIEW=0

crit()  { echo -e "${RED}[!] $*${NC}"; FINDINGS=$((FINDINGS+1)); }
warn()  { echo -e "${YELLOW}[?] $*${NC}"; REVIEW=$((REVIEW+1)); }
step()  { echo -e "\n${YELLOW}[$1] $2${NC}"; }
note()  { echo -e "    ${CYAN}↳${NC} $*"; }

MALICIOUS_FILES=(
    "temp_interactive_push.bat"
    "temp_auto_push.bat"
    "branch_structure.json"
)

LOADER_PATTERNS='curl |wget |base64 -d|base64 --decode|eval |node +-e|python +-c|powershell|Invoke-WebRequest|IEX|bitsadmin|certutil|/dev/tcp/|nc +-'

prune_expr=( \( -name node_modules -o -name .git -o -name dist -o -name build \
               -o -name coverage -o -name .next -o -name vendor -o -name .venv \) -prune )

echo -e "${YELLOW}[*] Void Dokkaebi / PolinRider scan — root: $(cd "$ROOT" 2>/dev/null && pwd || echo "$ROOT")${NC}"

# ---------------------------------------------------------------------------
step 1/8 "Known malicious filenames"
# ---------------------------------------------------------------------------
for f in "${MALICIOUS_FILES[@]}"; do
    while IFS= read -r -d '' hit; do
        crit "Dropped artifact: $hit"
    done < <(find "$ROOT" -type f -name "$f" -print0 2>/dev/null)
done

# ---------------------------------------------------------------------------
step 2/8 ".gitignore rules hiding those artifacts"
# ---------------------------------------------------------------------------
while IFS= read -r -d '' gi; do
    for pattern in "${MALICIOUS_FILES[@]}"; do
        if grep -qF "$pattern" "$gi" 2>/dev/null; then
            crit "Exclusion rule concealing an IOC in $gi"
            grep -HnF "$pattern" "$gi"
        fi
    done
done < <(find "$ROOT" "${prune_expr[@]}" -o -type f -name ".gitignore" -print0 2>/dev/null)

# ---------------------------------------------------------------------------
step 3/8 "Whitespace-padded payloads (all source, not just config files)"
# ---------------------------------------------------------------------------
while IFS= read -r -d '' f; do
    if grep -qE '[[:space:]]{50,}[^[:space:]]' "$f" 2>/dev/null; then
        crit "Whitespace-padded code in $f"
        grep -nE '[[:space:]]{50,}[^[:space:]]' "$f" 2>/dev/null | head -3 |
            sed 's/[[:space:]]\{40,\}/  <<< PADDING >>>  /' | cut -c1-200 |
            while IFS= read -r line; do note "$line"; done
    fi
done < <(find "$ROOT" "${prune_expr[@]}" -o -type f \
    \( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.ts' -o -name '*.tsx' \
       -o -name '*.jsx' -o -name '*.json' -o -name '*.sh' -o -name '*.bat' -o -name '*.ps1' \
       -o -name '*.yml' -o -name '*.yaml' \) -print0 2>/dev/null)

# ---------------------------------------------------------------------------
step 4/8 "Editor auto-run surfaces"
# ---------------------------------------------------------------------------
while IFS= read -r -d '' vf; do
    if grep -qE 'folderOpen|automationProfile|terminal\.integrated\.env' "$vf" 2>/dev/null; then
        crit "Auto-run trigger in $vf"
        grep -HnE 'folderOpen|automationProfile|terminal\.integrated\.env' "$vf" | head -5
    fi
done < <(find "$ROOT" \( -name node_modules -o -name .git \) -prune -o \
    -type f \( -path '*/.vscode/tasks.json' -o -path '*/.vscode/settings.json' \) -print0 2>/dev/null)

# ---------------------------------------------------------------------------
REPOS=()
while IFS= read -r -d '' gd; do
    REPOS+=( "$(dirname "$gd")" )
done < <(find "$ROOT" -name node_modules -prune -o -name .git -print0 2>/dev/null)

step 5/8 "Git hooks (${#REPOS[@]} repo(s) found)"
# ---------------------------------------------------------------------------
for repo in "${REPOS[@]}"; do
    hp=$(git -C "$repo" config --get core.hooksPath 2>/dev/null)
    if [ -n "$hp" ]; then
        note "$repo → core.hooksPath = $hp"
        case "$hp" in /*) hookdir="$hp" ;; *) hookdir="$repo/$hp" ;; esac
    else
        hookdir="$repo/.git/hooks"
    fi
    [ -d "$hookdir" ] || continue
    for h in "$hookdir"/*; do
        [ -f "$h" ] || continue
        case "$h" in *.sample) continue ;; esac
        if grep -qE "$LOADER_PATTERNS" "$h" 2>/dev/null; then
            crit "Loader command inside git hook $h"
            grep -HnE "$LOADER_PATTERNS" "$h" | head -5
        fi
    done
    if [ -n "$hp" ] && [ -n "$(ls -A "$repo/.git/hooks" 2>/dev/null | grep -v '\.sample$')" ]; then
        warn "$repo has non-sample files in .git/hooks despite core.hooksPath=$hp"
    fi
done

# ---------------------------------------------------------------------------
step 6/8 "npm install lifecycle scripts"
# ---------------------------------------------------------------------------
while IFS= read -r -d '' pj; do
    hits=$(grep -nE '"(preinstall|install|postinstall|prepare|prepublish)"[[:space:]]*:' "$pj" 2>/dev/null)
    [ -z "$hits" ] && continue
    if echo "$hits" | grep -qE "$LOADER_PATTERNS"; then
        crit "Loader command in install script: $pj"
        echo "$hits" | grep -E "$LOADER_PATTERNS"
    else
        note "$pj"
        echo "$hits" | while IFS= read -r line; do note "  $line"; done
    fi
done < <(find "$ROOT" -name node_modules -prune -o -type f -name package.json -print0 2>/dev/null)

# ---------------------------------------------------------------------------
step 7/8 "Git remotes and URL rewrites"
# ---------------------------------------------------------------------------
for repo in "${REPOS[@]}"; do
    rw=$(git -C "$repo" config --get-regexp 'url\..*\.insteadof' 2>/dev/null)
    if [ -n "$rw" ]; then
        crit "URL rewrite rule in $repo — every push may be redirected"
        echo "$rw"
    fi
    pushes=$(git -C "$repo" remote -v 2>/dev/null | awk -v r="$repo" '/\(push\)/ {print "    ↳ " r " push → " $2}')
    if [ -n "$pushes" ]; then echo "$pushes"; else note "$repo — no remote (local-only)"; fi
done

# ---------------------------------------------------------------------------
step 8/8 "Minified / single-line blobs (heuristic — expect false positives)"
# ---------------------------------------------------------------------------
while IFS= read -r -d '' f; do
    long=$(awk 'length($0)>1000 {print FNR" ("length($0)" chars)"; exit}' "$f" 2>/dev/null)
    [ -n "$long" ] && warn "Long single line in $f — line $long"
done < <(find "$ROOT" "${prune_expr[@]}" -o -type f \
    \( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.ts' \) -print0 2>/dev/null)

# ---------------------------------------------------------------------------
echo -e "\n${YELLOW}==================================================${NC}"
if [ "$FINDINGS" -eq 0 ] && [ "$REVIEW" -eq 0 ]; then
    echo -e "${GREEN}[✓] Clean. No indicators of compromise.${NC}"
elif [ "$FINDINGS" -eq 0 ]; then
    echo -e "${GREEN}[✓] No hard indicators.${NC} ${YELLOW}$REVIEW heuristic hit(s) above to eyeball.${NC}"
else
    echo -e "${RED}[X] $FINDINGS hard indicator(s), $REVIEW heuristic hit(s).${NC}"
    echo -e "${YELLOW}[*] Rotate GitHub tokens and SSH keys now, then clean the flagged files.${NC}"
fi
echo -e "${YELLOW}==================================================${NC}"

[ "$FINDINGS" -eq 0 ]
