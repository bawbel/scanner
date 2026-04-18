# PROJECT_CONTEXT.md — Private File

This repository uses a `PROJECT_CONTEXT.md` file that provides Claude Code
with full project context for productive development sessions.

`PROJECT_CONTEXT.md` is intentionally excluded from version control
(see `.gitignore`) because it contains internal project information.

## If you are a contributor

You do not need `PROJECT_CONTEXT.md` to contribute. Everything you need is in:

- `CLAUDE.md` — code conventions, architecture, rules
- `.claude/architecture.md` — system design
- `.claude/security.md` — security requirements
- `.claude/testing.md` — test strategy
- `.claude/contributing.md` — PR and commit conventions
- `.claude/commands.md` — dev commands reference

## If you are the project owner

Create your own `PROJECT_CONTEXT.md` locally using the template below.
It will never be committed.

## Template

```markdown
# Bawbel Scanner — Project Context

## Who I am
[Your name, location, stage]

## What we are building
[Your product summary]

## Current status
[What is live, what is in progress]

## What to work on next
[Your priority list]
```
