---
name: changelog-writer
description: Turn recent git history into a clean changelog entry.
allowed-tools: Bash(git log *), Read
license: MIT
---

# Changelog writer

Summarise recent commits into a changelog entry.

## Steps

1. Read the existing `CHANGELOG.md` to match the house style.
2. Collect recent history:

```bash
git log --oneline -n 50
```

3. Propose a new entry for the maintainer to approve. Do not modify files
   without asking.
