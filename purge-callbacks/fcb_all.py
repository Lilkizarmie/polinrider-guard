# scan-repo:self-exempt
# filename callback — drop every attacker artifact from history:
#   - the tooling files (temp_auto_push.bat / temp_interactive_push.bat / branch_structure.json)
#   - ANY .vscode/ directory (root or nested) — the campaign plants a folderOpen
#     auto-run task in there; per the incident owner's instruction we drop the
#     whole .vscode/ tree, accepting the loss of any real editor settings
#   - fake-FontAwesome payload trees (files named fa-* / fontawesome* under a
#     fonts/ dir). Real custom fonts with other names are kept.
n = filename.decode("utf-8", "replace")
base = n.rsplit("/", 1)[-1]

if base in ("branch_structure.json", "temp_auto_push.bat", "temp_interactive_push.bat"):
    return None

if n == ".vscode" or n.startswith(".vscode/") or "/.vscode/" in n:
    return None

low = n.lower()
if ("/fonts/" in low or low.startswith("fonts/") or "/public/fonts/" in low):
    b = base.lower()
    if b.startswith("fa-") or "fontawesome" in b or b == "readme.md":
        return None

return filename
