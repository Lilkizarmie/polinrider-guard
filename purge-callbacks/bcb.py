# scan-repo:self-exempt
# blob callback: strip the appended obfuscated RAT-stager payload from build
# configs / source files, and remove the attacker's tooling lines from
# .gitignore. Identifiers in the payload are randomized per infection, so the
# cut point is found STRUCTURALLY (a wall of tab/space padding, or an absurdly
# long appended line, or the payload's string-table IIFE) as well as by a broad
# token set — then everything from the earliest indicator onward is removed.
import re
try:
    t = blob.data.decode("utf-8")
except Exception:
    return
orig = t

# 1 ── .gitignore: drop the attacker's three tooling entries
_drop = {"branch_structure.json", "temp_auto_push.bat", "temp_interactive_push.bat"}
if any(d in t for d in _drop):
    t = "\n".join(ln for ln in t.split("\n") if ln.strip() not in _drop)

# 2 ── appended obfuscator payload
_TOKENS = (
    "_0x3d50aa", "NONCE_FANOUT", "BLOCK_MULTIPLE", "windowsHide",
    "eth_getBlockByNumber", "eth_getTransactionCount", "/0x/cl", "/0x/ls",
    "/$/boot", "0xa322E5f39aDC2490Ef6f0121063eD311D3080e1a",
    "'detached':!![]", '"detached":!![]', "child_process", "Cot%3t=shtP",
    "rmcej%otb%", ".unref()",
)
idx = []

# the wall of >=40 tab/space chars — the reliable delimiter (may sit mid-line,
# right after a real line of code, so this must be checked before line length)
m = re.search(r"[ \t]{40,}", t)
if m:
    idx.append(m.start())

for tok in _TOKENS:
    p = t.find(tok)
    if p != -1:
        idx.append(p)

# the payload's string-table IIFE:  function <id>(){const <id>=['<hex>',...
m = re.search(r"[ \t\n;]function\s+[A-Za-z_$][\w$]*\s*\(\s*\)\s*\{\s*(?:var|const|let)?\s*[A-Za-z_$][\w$]*\s*=\s*\[\s*['\"][0-9a-fA-F]{4,}", t)
if m:
    idx.append(m.start())

# a bare  global['x']= / global.x = <ident>  handoff mid-file
m = re.search(r"global\s*(?:\[\s*['\"][^'\"]+['\"]\s*\]|\.\w+)\s*=\s*[A-Za-z_$]", t)
if m and m.start() > 40:
    idx.append(m.start())

# a single absurdly long line not already explained above — cut within it, not
# at its start (real code may precede the payload on the same line)
for _lm in re.finditer(r"[^\n]{1500,}", t):
    _seg = _lm.group(0)
    _w = re.search(r"[ \t]{20,}|;\s*(?=[A-Za-z_$])", _seg)
    idx.append(_lm.start() + (_w.start() if _w else 400))
    break

idx = [i for i in idx if i >= 0]
if idx:
    cut = min(idx)
    while cut > 0 and t[cut - 1] in " \t\r\n":
        cut -= 1
    t = t[:cut].rstrip()
    # the attacker prepends this ESM shim so its require() calls resolve; a
    # stock vite/tailwind/babel/postcss/eslint config never needs it.
    for shim in (
        "import { createRequire } from 'module';\n\nconst require = createRequire(import.meta.url);",
        "import { createRequire } from 'module';\nconst require = createRequire(import.meta.url);",
        "import { createRequire } from \"module\";\nconst require = createRequire(import.meta.url);",
    ):
        if shim in t:
            t = t.replace(shim, "").strip()
    t = (t + "\n") if t.strip() else ""

if t != orig:
    blob.data = t.encode("utf-8")
