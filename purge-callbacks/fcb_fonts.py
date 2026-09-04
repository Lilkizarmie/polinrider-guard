# filename callback, extended variant: for repos where the attacker also
# planted a fake-font tree. Drops the entire attacker-added public/fonts/
# tree (fake FontAwesome — JS, not fonts) and the attacker-planted .vscode/
# (folderOpen auto-run task), in addition to the tooling files fcb.py drops.
if filename in (b"branch_structure.json", b"temp_auto_push.bat", b"temp_interactive_push.bat"):
    return None
if filename.startswith(b"public/fonts/") or filename.startswith(b".vscode/"):
    return None
return filename
