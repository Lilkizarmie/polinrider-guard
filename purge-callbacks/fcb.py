# filename callback (config-carrier repos): drop the attacker's tooling files.
if filename in (b"branch_structure.json", b"temp_auto_push.bat", b"temp_interactive_push.bat"):
    return None
return filename
