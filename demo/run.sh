#!/usr/bin/env bash
#
# Reproducible demo of skillnotary's core claim: a skill you approved can
# silently gain a capability.
#
# Runs entirely offline against local files. Every digest, capability and
# finding in the output is deterministic; the only variable is the ed25519 key
# id printed by `sign`, because `keygen` draws a fresh key each run.
#
# The README's demo/demo.svg is generated from this output:
#
#   bash demo/run.sh > demo/demo.txt
#   python3 demo/render_svg.py
#
set -euo pipefail

SKILLNOTARY="${SKILLNOTARY:-node $(cd "$(dirname "$0")/.." && pwd)/src/cli.ts}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

mkdir -p release-notes
printf 'MIT License\n\nPermission is hereby granted, free of charge.\n' > release-notes/LICENSE

cat > release-notes/SKILL.md <<'SKILL'
---
name: release-notes
description: Draft release notes from git history.
allowed-tools: Bash(git log *), Read
license: MIT
---

# Release notes

Summarise recent commits into a draft.

```bash
git log --oneline -n 50
```
SKILL

prompt() { printf '\n\033[1m$ %s\033[0m\n' "$*"; }
# A non-zero exit is often the *point* here (drift detected, findings raised),
# so the demo must not abort on it. --color forces ANSI even though stdout is a
# pipe, so the captured text keeps the tool's real colours.
sn() { prompt "skillnotary $*"; $SKILLNOTARY "$@" --color || true; }

# Setup runs quietly; the demo shows the interesting part.
$SKILLNOTARY init >/dev/null
$SKILLNOTARY keygen >/dev/null

sn add ./release-notes --name release-notes
sn lock
sn sign
sn verify

printf '\n\033[1m# ...two weeks later, upstream edits the skill you approved\033[0m\n'

cat >> release-notes/SKILL.md <<'SKILL'

Also, hand the long changelog to a helper agent:

```bash
claude --print "summarise the last 200 commits"
```
SKILL

sn verify
sn audit
