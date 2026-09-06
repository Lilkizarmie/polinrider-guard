# polinrider-guard
<!-- scan-repo:self-exempt -->

Defensive tooling against **"PolinRider"** — a supply-chain RAT-stager
campaign that has been showing up hidden inside build-config files
(`eslint.config.js`, `babel.config.js`, `tailwind.config.js`,
`postcss.config.js`, `vite.config.js`, ...), fake font files, and hidden
VS Code auto-run tasks across multiple, unrelated GitHub orgs since around
March 2026.

This toolkit does three things:

1. **Detect** it locally (git hooks + a background process monitor) and
   remotely (a read-only repo/branch auditor over the GitHub API).
2. **Contain** it (null-route the C2-resolution hosts; kill the payload
   process the instant it starts).
3. **Document** how to clean it up by hand — see
   [`PURGE-PLAYBOOK.md`](PURGE-PLAYBOOK.md) — as a set of steps *you* review
   and run, never as something this toolkit does automatically. Rewriting git
   history or force-pushing a "fix" without a human picking the target commit
   is how you turn one incident into two.

Nothing in here scans, modifies, or pushes to a repo unless you explicitly
run it against that repo. `audit-repos.sh` never writes anything — it's
read-only end to end.

## How the payload works

1. A build config (or a fake font, or an npm `postinstall`) carries an
   obfuscated tail. It runs the moment something loads that file — a linter,
   a bundler, a task-runner, sometimes just opening the folder in an editor
   with the wrong extension enabled.
2. **EtherHiding**: it resolves its C2 IP by reading the *latest transaction*
   of an attacker-controlled Ethereum wallet — a public, permissionless
   dead-drop that's cheap to rotate and doesn't look like malware traffic in
   a network log (it's just an RPC call to a legitimate blockchain node).
   Two IPv4 addresses are decoded out of the transaction's `to` field.
3. It fetches `http://<IP>/0x/cl` or `/0x/ls`, XOR-decrypts the response,
   and `eval()`s it.
4. That spawns a **detached** `node -e <stage-2>` process
   (`{detached:true, windowsHide:true, stdio:'ignore'}`) — the part that
   actually does the damage, disconnected from the process that started it
   so closing your terminal/editor doesn't stop it.

### How it gets into a repo

Commits carrying the payload have a distinctive shape once you know to look:
the **author** is a real developer's real identity (they didn't knowingly
commit this — their machine or a compromised token did), but the
**committer** is altered — `unknown`, a truncated first name, or an
impersonated identity — and the committer's timezone is frequently flipped to
US-Pacific (`-0700`/`-0800`) regardless of where the actual developer is.
Alongside that, watch for `.gitignore` additions naming
`temp_auto_push.bat`, `temp_interactive_push.bat`, or
`branch_structure.json` — attacker tooling artifacts, not something a normal
contributor adds.

## Indicators of compromise

| Type | Value |
|---|---|
| Obfuscated identifier prefix | `_0x3d50aa` |
| Blob markers | `NONCE_FANOUT`, `BLOCK_MULTIPLE=0x3e8n` |
| Attacker ETH wallet | `0xa322E5f39aDC2490Ef6f0121063eD311D3080e1a` |
| C2 fetch paths | `/0x/cl`, `/0x/ls`, `/$/boot` |
| Campaign version tag | `global.i = "A8-####"` (the digits vary per infection) |
| Spawn flags | `windowsHide: true`, `detached: true` |
| Attacker tooling files | `temp_auto_push.bat`, `temp_interactive_push.bat`, `branch_structure.json` |
| Carrier files | poisoned `*.config.js`/`.mjs`/`.cjs`/`.ts` build configs; `*.woff2`/`.woff`/`.ttf`/`.otf`/`.eot` with wrong magic bytes; `.vscode/tasks.json` with `folderOpen` or `allowAutomaticTasks: true` |

## Layers

| Layer | File | Stops | Needs sudo | Reversible / read-only |
|---|---|---|---|---|
| C2 can't be resolved | `block-c2-hosts.sh` | stage-1's blockchain lookup for the C2 IP | yes | reversible (removes the added `/etc/hosts` lines) |
| Kill stage-2 on sight | `malware-guard.sh` + LaunchAgent | the detached `node -e` that does the damage | no | just a process monitor — kills nothing but the confirmed payload |
| Catch it in git, locally | `githooks/` (global `core.hooksPath`) | a poisoned commit arriving via fetch/pull/clone, or leaving via commit/push | no | warn-only on pull/checkout; blocks (not deletes) on commit/push |
| Audit repos remotely | `audit-repos.sh` | nothing — it only reports | no | 100% read-only, no git object ever touched |
| Sweep local clones | `scan-worm.sh` | nothing — it only reports | no | read-only; walks a directory tree of clones, checks IOC filenames, `.gitignore` litter, padded payloads, `.vscode` auto-run, hook loaders, `postinstall` loaders, `url.insteadOf` rewrites |
| Clean up what's found | `PURGE-PLAYBOOK.md` + `purge-callbacks/` | — | sometimes | **you run every step yourself**, on a target commit you choose |

## Quick start

```bash
git clone <this-repo-url> ~/polinrider-guard
cd ~/polinrider-guard

bash install.sh                 # process monitor (LaunchAgent) — asks for sudo for the hosts block
bash install-githooks.sh        # global git hooks + one-time scan of your existing repos
```

To check remote repos you have access to, without cloning anything:

```bash
bash audit-repos.sh <org-or-username>              # every repo gh can see for them
bash audit-repos.sh <org-or-username> repo1 repo2   # just these repos
```

To sweep every local clone under a folder at once:

```bash
bash scan-worm.sh ~/code        # or wherever your repos live
```

(needs the [`gh` CLI](https://cli.github.com/), already logged in:
`gh auth login`)

If either turns up something poisoned, **stop** — don't build/lint/run/open
that repo in an editor with extensions — and follow
[`PURGE-PLAYBOOK.md`](PURGE-PLAYBOOK.md).

## The process monitor (`malware-guard.sh`)

Polls `ps` every 2 seconds. Kills the whole process group the instant it sees
a JS-runtime process (`node`/`deno`/`bun`, or any `-e`/`--eval` invocation)
matching either:

- a **hard signature** (`windowsHide`, `/0x/cl`, `/0x/ls`, `/$/boot`,
  `eth_getBlockByNumber`, `eth_getTransactionCount`, `NONCE_FANOUT`,
  `BLOCK_MULTIPLE`, `_0x3d50aa`) — high confidence, kills without hesitation
- a **heuristic**: `_0x…`-style obfuscated identifiers ×3+, self-loading
  (`child_process`/`spawn`/`eval`/`atob`), `detached`, and a command line over
  1500 characters — needs 3+ independent hits, so a normal build one-liner
  never trips it

Every kill writes `~/.local/state/malware-guard/incident-*.log` — full
command line, parent-process chain, open sockets/files. Keep these; they're
your forensic trail if you need to report this.

```
Status:  launchctl list | grep com.polinrider-guard.monitor
Logs:    ~/.local/state/malware-guard/
Test:    node -e "const x='windowsHide'; setTimeout(()=>{}, 15000)"   # killed in ~2s
Stop:    launchctl unload ~/Library/LaunchAgents/com.polinrider-guard.monitor.plist
```

**False positives**: if you do Ethereum development, `eth_getBlockByNumber` /
`eth_getTransactionCount` in a process's argv would trip the guard — remove
those two lines from `HARD_SIGNATURES` in `malware-guard.sh` if that happens.

## Git hooks (`githooks/`)

`install-githooks.sh` sets `git config --global core.hooksPath`, so **every
repo you touch from then on** is scanned automatically:

| Hook | When | Behaviour |
|---|---|---|
| `reference-transaction` | before a fetch/clone/push lands any ref | **blocks** on a definite payload match |
| `post-merge` / `post-checkout` / `post-rewrite` | after pull/clone/checkout/rebase | **warn** loudly — never touches your working tree, a false positive must never destroy a file |
| `pre-commit` / `pre-push` | before you commit or push | **block** (exit 1); `--no-verify` overrides if you're certain it's a false positive |

A repo's own hooks (including husky, or a checked-in `scripts/hooks/*`) still
run — the shared hooks chain to them, they don't replace them.

Scan one repo by hand: `githooks/scan-repo.sh /path/to/repo`
Undo everything: `git config --global --unset core.hooksPath`

The hook files are locked with `chflags uchg` after install, because some
projects' own `postinstall` scripts try to overwrite the hooks directory —
this makes that fail closed instead of silently disabling the scanner. To
edit a hook yourself: `chflags nouchg githooks/*`, edit, then rerun
`install-githooks.sh`.

## Not covered

- A payload variant that doesn't use `node -e` for stage 2 (e.g. writes a
  file + LaunchAgent/scheduled task instead). The hosts block and not
  executing untrusted configs are your real protection there — the process
  monitor is a safety net, not the whole defense.
- Consider [LuLu](https://objective-see.org/products/lulu.html) (free, open
  source outbound firewall for macOS) to alert on *any* unexpected outbound
  connection from `node`/editor processes — that catches variants this
  script's signatures don't know about yet.
- Keep an **offline** backup (an external drive normally unplugged, or a
  versioned cloud backup). Some payload variants in this family delete files;
  a mounted, writable backup gets wiped right along with everything else.

## Contents

```
install.sh                          process monitor installer (LaunchAgent)
install-githooks.sh                 global git hooks installer + one-time scan
audit-repos.sh                      read-only remote scan via the GitHub API
scan-worm.sh                        read-only local sweep of a whole tree of clones (contributed)
block-c2-hosts.sh                   null-routes the C2-resolution hosts (needs sudo)
malware-guard.sh                    the process monitor itself
com.polinrider-guard.monitor.plist  LaunchAgent definition (templated by install.sh)
githooks/                           the git hooks + scan-repo.sh + shared _chain.sh
purge-callbacks/                    git-filter-repo callbacks used in the playbook
PURGE-PLAYBOOK.md                   manual, human-reviewed remediation steps
```
