# commit callback: undo the attacker's forged committer identity.
# The tool preserves the AUTHOR line but the COMMITTER line ends up as its own
# machine (name truncated / "unknown", and a US-Pacific -0700/-0800 offset).
# Real commits here have committer == author, except GitHub's own merge commits.
_auth_off = commit.author_date.split(b" ")[-1] if b" " in commit.author_date else b""
_comm_off = commit.committer_date.split(b" ")[-1] if b" " in commit.committer_date else b""
if commit.committer_name != b"GitHub" and commit.committer_email != b"noreply@github.com":
    if (commit.committer_name != commit.author_name
            or commit.committer_email != commit.author_email
            or _comm_off != _auth_off):
        commit.committer_name = commit.author_name
        commit.committer_email = commit.author_email
        commit.committer_date = commit.author_date
