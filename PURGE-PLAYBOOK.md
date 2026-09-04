# PURGE-PLAYBOOK.md — manually cleaning a poisoned repo

<!-- scan-repo:self-exempt -->

**Read this whole file before running anything.** Every command here rewrites
git history or force-updates a branch — both are destructive to anyone who
still has the old history, and none of it should run unattended. Nothing in
this toolkit auto-purges a repo for you; you drive every step and pick the
target commit yourself.

Before you touch a single repo, do the one thing that actually matters:

> **Find out how the payload got in, and revoke that access.** A cleaned
> repo with the same compromised token/SSH key/machine behind it will be
> reinfected — sometimes within hours. Cleaning code is cosmetic until the
> credential or machine that pushed it is dealt with. See
> [Root-cause first](#root-cause-first-this-is-not-optional) below.

## Contents

1. [Root-cause first](#root-cause-first-this-is-not-optional)
2. [Confirm what you're dealing with](#1-confirm-what-youre-dealing-with)
3. [Pick your method](#2-pick-your-method)
4. [Method A — git-filter-repo (rewrite history, keep real commits)](#method-a--git-filter-repo)
5. [Method B — GitHub API purge (no local clone, works on a bad connection)](#method-b--github-api-purge)
6. [After the purge](#3-after-the-purge)

---

## Root-cause first (this is not optional)

For each poisoned repo, before or alongside cleaning it:

- **Org owners**: review Settings → Collaborators & teams and Settings →
  Personal access tokens for anything unfamiliar or over-scoped. Revoke and
  reissue. (Git-event audit logging — who pushed what, when — is a GitHub
  **Enterprise Cloud** feature; a standard org/team plan doesn't have it, so
  member/token review is usually the only lever you have.)
- **Everyone with push access to the repo**: assume the machine that pushed
  the poisoned commit is compromised until proven otherwise. Run
  `malware-guard.sh` and `scan-repo.sh` there, rotate every credential that
  machine held (GitHub PAT/SSH key, npm token, cloud keys), and seriously
  consider re-imaging it if you can't be sure it's clean.
- **Branch protection**: turn on "Require pull request before merging" and
  "Do not allow force pushes" on default/release branches once the repo is
  clean, so a compromised machine can't silently force-push the payload back.

None of this is scriptable safely — it's account/people review, not code.

## 1. Confirm what you're dealing with

```bash
./audit-repos.sh <owner> [repo ...]      # read-only, every branch, no clone needed
# or, with a local clone:
githooks/scan-repo.sh /path/to/repo
```

Note **which branches** are poisoned and, ideally, the last known-good commit
SHA on each (check `git log` / the GitHub commit history around when the
poisoned commit landed — look for the forged-committer pattern below).

**Recognizing a forged commit**: the *author* is usually the real developer
(their name/email are genuine — they didn't knowingly commit this), but the
*committer* is altered — `unknown`, a truncated first name, or an impersonated
identity — and the committer timezone is often flipped to US Pacific
(`-0700`/`-0800`) regardless of the actual developer's timezone. A real commit
from the same person, minutes earlier or later, usually still has their real
committer identity and timezone — that contrast is the tell.

## 2. Pick your method

| | Method A: git-filter-repo | Method B: GitHub API |
|---|---|---|
| Needs a local clone | yes | no |
| Works on a bad/unreliable connection | not well | yes — pure small HTTPS calls |
| Keeps real commits, only strips the payload | yes (surgical) | only with the "forward-fix" variant below |
| Best for | a repo with real history worth preserving around the bad commit(s) | the same, when clone/push keeps failing, or a repo that's poisoned from its root commit |

Both end the same way: force-updating the branch ref to point at clean
history. **Force-push rewrites the remote branch — anyone who has it checked
out needs to `git fetch` and reset their local branch to match, or they'll
recreate the poisoned history the next time they push.** Tell your
collaborators before you do this.

## Method A — git-filter-repo

Needs [`git-filter-repo`](https://github.com/newren/git-filter-repo)
(`brew install git-filter-repo` / `pip install git-filter-repo`).

```bash
git clone --no-local <url> /path/to/quarantine/<repo>   # work on a throwaway copy
cd /path/to/quarantine/<repo>

git filter-repo --force \
  --blob-callback   "$(cat /path/to/polinrider-guard/purge-callbacks/bcb.py)" \
  --filename-callback "$(cat /path/to/polinrider-guard/purge-callbacks/fcb.py)" \
  --commit-callback  "$(cat /path/to/polinrider-guard/purge-callbacks/ccb.py)"
```

(Swap in `fcb_fonts.py` for `fcb.py` if `scan-repo.sh` also flagged a fake-font
tree or a planted `.vscode/` task in this repo.)

What each callback does (read them before running — they're short):

- **`bcb.py`** (blob callback) — strips the payload tail from a poisoned build
  config (everything after the tab-wall / obfuscated append), and removes any
  attacker-added `.gitignore` lines. Leaves the rest of the file untouched.
- **`fcb.py`** (filename callback) — drops the attacker's tooling files
  (`branch_structure.json`, `temp_auto_push.bat`, `temp_interactive_push.bat`)
  from history entirely. Use **`fcb_fonts.py`** instead when the repo also has
  a fake-font tree (`public/fonts/...` that's actually JS) or a planted
  `.vscode/` auto-run task — it does everything `fcb.py` does, plus drops
  those.
- **`ccb.py`** (commit callback) — normalizes a forged committer identity back
  to the real author's identity **generically**, by comparing
  `committer.name/email/offset` against `author.name/email/offset` and fixing
  the committer only when they differ (and the committer isn't a legitimate
  `GitHub <noreply@github.com>` merge-commit committer). It does not hardcode
  any person's name — it works on the pattern, not a lookup table.

**Verify before pushing anything:**

```bash
githooks/scan-repo.sh .          # must come back clean
git log --oneline -20            # sanity-check real commits are still there
```

Then push the cleaned branch. If `git push` fails on a bad connection, use
Method B's ref-update step instead — it accepts any local commit SHA,
including one produced by filter-repo.

## Method B — GitHub API purge

No local clone required. This is the technique to reach for when `git push` /
`git clone --mirror` are failing with connection errors — it's pure small
HTTPS calls, no pack transfer.

**B1 — you already have a clean commit SHA** (from a healthy fork, an earlier
good commit, or a Method-A result you have the SHA for):

```bash
gh api --method PATCH "repos/<owner>/<repo>/git/refs/heads/<branch>" \
  -f sha=<clean-commit-sha> -F force=true
```

That's the entire force-update — one HTTP PATCH, no local objects needed as
long as `<clean-commit-sha>` already exists on GitHub's side (e.g. it's
reachable from another branch, a fork, or a tag).

**B2 — "forward-fix": swap one poisoned blob for a clean one, on top of
current history** (keeps the payload in old history, but immediately stops it
executing — use this when you need the branch safe *right now* and will do a
full history rewrite later):

```bash
# 1. Get the current tree
base_tree=$(gh api repos/<owner>/<repo>/branches/<branch> --jq .commit.commit.tree.sha)

# 2. Upload the clean replacement file's content as a new blob
blob_sha=$(gh api --method POST repos/<owner>/<repo>/git/blobs \
  -f content="$(base64 < clean-eslint.config.js)" -f encoding=base64 --jq .sha)

# 3. Build a new tree that swaps just that one path
new_tree=$(gh api --method POST repos/<owner>/<repo>/git/trees \
  -f base_tree="$base_tree" \
  -f "tree[][path]=eslint.config.js" -f "tree[][mode]=100644" \
     -f "tree[][type]=blob" -f "tree[][sha]=$blob_sha" \
  --jq .sha)

# 4. Commit it on top of the current branch head
parent=$(gh api repos/<owner>/<repo>/branches/<branch> --jq .commit.sha)
new_commit=$(gh api --method POST repos/<owner>/<repo>/git/commits \
  -f message="security: remove RAT-stager payload from eslint.config.js" \
  -f tree="$new_tree" -f "parents[]=$parent" --jq .sha)

# 5. Point the branch at it
gh api --method PATCH repos/<owner>/<repo>/git/refs/heads/<branch> \
  -f sha="$new_commit" -F force=true
```

**B3 — rebuild a repo that's poisoned from its root commit** as a single
clean commit (only when there's no clean history to reset to at all — you
lose history this way, so prefer A or B1/B2 whenever a clean point exists):
build a full tree of every *known-good* file via repeated `git/trees` calls
(or one call with the full `tree[]` array), commit it with no parent, then
force the branch ref (B1's PATCH) at that new root commit.

After any of these, re-run `audit-repos.sh` or `scan-repo.sh` against the
result to confirm it's actually clean before telling anyone it's safe to pull.

## 3. After the purge

- [ ] `audit-repos.sh` (or `scan-repo.sh` on a fresh clone) comes back clean
- [ ] Every collaborator has been told to `git fetch` + hard-reset their local
      branch to the new remote history (not `git pull` — that can recreate a
      merge of old and new history)
- [ ] The credential/machine that pushed the payload has been rotated/cleaned
      (see [Root-cause first](#root-cause-first-this-is-not-optional))
- [ ] Branch protection (block force-push, require PR review) is turned on
- [ ] Everyone installs the local defenses in this toolkit (`install.sh`,
      `install-githooks.sh`) so a re-infection is caught immediately instead
      of silently landing again
