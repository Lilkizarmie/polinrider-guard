# scan-repo:self-exempt
# blob callback: strip the obfuscated RAT payload appended to build configs /
# source files, and remove the attacker's tooling lines from .gitignore.
try:
    t = blob.data.decode("utf-8")
except Exception:
    return

changed = False

# 1 — attacker appended these to .gitignore in every injection commit
if "temp_auto_push.bat" in t or "branch_structure.json" in t or "temp_interactive_push.bat" in t:
    drop = {"branch_structure.json", "temp_auto_push.bat", "temp_interactive_push.bat"}
    kept = [ln for ln in t.split("\n") if ln.strip() not in drop]
    nt = "\n".join(kept)
    if nt != t:
        t = nt
        changed = True

# 2 — the javascript-obfuscator blob, appended after ~1000 tabs
markers = ("global.i = 'A8-", "global.i='A8-", ";const _0x3d50aa",
           "const _0x3d50aa=_0x4540", "global['r']=require", "NONCE_FANOUT",
           "_0x3d50aa")
if any(m in t for m in markers):
    cut = len(t)
    for m in markers:
        i = t.find(m)
        if i != -1:
            j = i
            while j > 0 and t[j-1] in " \t":
                j -= 1
            cut = min(cut, j)
    head = t[:cut].rstrip()
    head = head + "\n" if head else ""
    for shim in (
        "import { createRequire } from 'module';\n\nconst require = createRequire(import.meta.url);\n\n",
        "import { createRequire } from 'module';\nconst require = createRequire(import.meta.url);\n",
    ):
        if head.startswith(shim):
            head = head[len(shim):]
    t = head
    changed = True

if changed:
    blob.data = t.encode("utf-8")
