# How to Use Bawbel's Engineering System

This file explains the sequence for using CLAUDE.md, LANGUAGE.md,
ARCHITECTURE.md, PRODUCT.md, the skills, PRDs, ADRs, and handoffs together.
Read this once. Then it becomes instinct.

---

## The four governance files and what they answer

| File | Question it answers | When to read |
|---|---|---|
| `CLAUDE.md` | How do we work? | Every session start |
| `LANGUAGE.md` | What do we call things? | Before naming anything |
| `ARCHITECTURE.md` | Where does code go? | Before writing any code |
| `PRODUCT.md` | Why are we building this? | When making a prioritization decision |

Claude Code reads `CLAUDE.md` automatically. The others are referenced from it.

---

## Session sequences

### Starting a new session (terminal / Claude Code)

```
1. cd bawbel-scanner
2. git pull origin main
3. pytest tests/ -q               ← must be green before anything else
4. cat docs/agents/handoffs/<latest>.md   ← where we left off
5. cat CLAUDE.md                  ← confirm current task queue
6. Start on the task listed under "Current priority tasks"
```

If `pytest tests/ -q` is not green: stop. Run `/diagnose` before touching
any code. A broken baseline means you cannot tell if your changes broke
something.

---

### Implementing a task (the standard loop)

```
1. Read CLAUDE.md → find the current task
2. Read LANGUAGE.md → confirm naming for new code
3. Read ARCHITECTURE.md → confirm which layer
4. Run /zoom-out if the file is unfamiliar
5. Write the failing test
6. pytest tests/unit/<file>.py -x -q  → MUST FAIL
7. Write minimum implementation
8. pytest tests/unit/<file>.py -x -q  → MUST PASS
9. Refactor
10. pytest tests/ -x -q               → full suite green
11. git commit
12. Update ARCHITECTURE.md if module shape changed
```

---

### Designing something new (before writing a line of code)

```
1. Run /grill-with-docs
   → answers 10 questions about the design
   → updates LANGUAGE.md with new terms inline
   → surfaces ADR conflicts
   → produces: interface signatures, test names, layer placement

2. Run /design-an-interface (if a module API is needed)
   → generates 3 parallel designs
   → picks the deepest one

3. Run /to-prd
   → synthesizes the conversation into docs/agents/prds/prd-NN-[slug].md
   → creates a GitHub issue

4. Run /to-issues
   → breaks the PRD into vertical slices
   → creates docs/agents/prds/prd-NN-tasks.md
   → creates individual GitHub issues

5. Pick TASK-01 from the task board
6. Follow the implementing loop above
```

---

### Finding architecture improvement opportunities

```
1. Run /improve-codebase-architecture
   → surfaces 3-5 deepening candidates from scanner/scanner.py
   → applies the deletion test to each
   → recommends which to extract first

2. Run /grill-with-docs on the chosen candidate

3. Follow the design → prd → issues → implement sequence
```

---

### Debugging a broken test or unexpected behavior

```
1. Run /diagnose
   → reproduce → minimize → hypothesize → confirm → fix
   → adds regression test automatically
   → adds WHY comment in code
```

---

### Ending a session

```
1. Run /handoff
   → writes docs/agents/handoffs/YYYY-MM-DD-HHMM.md
   → records: what was done, test status, next action, open questions

2. git push
```

---

### Starting a PR

```
1. git checkout -b fix/issue-N-slug
2. Implement following the standard loop
3. pytest tests/ -x -q  → fully green
4. ruff check scanner/ && mypy scanner/core/
5. Update ARCHITECTURE.md if module shape changed
6. git push && open PR: "[issue-N] short description"
```

---

## When to use each skill

| You want to... | Use this skill |
|---|---|
| Design a new feature | `/grill-with-docs` → `/to-prd` → `/to-issues` |
| Design a module API | `/design-an-interface` |
| Implement a task | `/tdd` |
| Find what to refactor | `/improve-codebase-architecture` |
| Fix a bug | `/diagnose` |
| Understand unfamiliar code | `/zoom-out` |
| End or start a session | `/handoff` |
| Protect against dangerous git | `/git-guardrails` |
| First time setup | `/setup-bawbel-skills` |

---

## When to update each governance file

| File | Update when... |
|---|---|
| `CLAUDE.md` | Current task queue changes, new hard rules added |
| `LANGUAGE.md` | New domain term needed, term definition refined |
| `ARCHITECTURE.md` | Module added/moved, migration step completed, new diagram needed |
| `PRODUCT.md` | Phase completed, competitive landscape changes, new research direction |
| `docs/adr/` | Architectural decision made, previously rejected approach resurfaced |
| `docs/agents/prds/` | New PRD created or completed |

---

## The file reading order for a contributor joining the project

```
1. README.md              → what is Bawbel
2. CONTRIBUTING.md        → how to contribute
3. CLAUDE.md              → how we work (rules and task queue)
4. LANGUAGE.md            → what things are called
5. ARCHITECTURE.md        → where code lives
6. PRODUCT.md             → why we are building this
7. docs/guides/evidence-lifecycle.md  → (if touching Finding or output)
8. docs/guides/refactoring-guide.md   → (if extracting from scanner.py)
9. docs/adr/              → decisions already made
10. docs/agents/prds/     → active work in progress
```

A contributor does not need to read all ten files before opening a PR.
They need to read the first four. The rest are reference material.

---

## File ownership summary

```
CLAUDE.md           → engineering rules        committed, update freely
LANGUAGE.md         → domain vocabulary        committed, update with care
ARCHITECTURE.md     → module map               committed, update on every PR
PRODUCT.md          → product context          committed, update on phase changes
CONTRIBUTING.md     → contributor guide        committed, stable
PROJECT_STRUCTURE.md → directory reference     committed, stable
bawbel.yml          → scanner config           committed
.bawbelignore       → suppression config       committed
.gitignore          → git exclusions           committed

docs/adr/           → architecture decisions   committed, append-only
docs/agents/prds/   → active PRDs              committed
docs/agents/handoffs/ → session notes          GITIGNORED
docs/guides/        → how-to guides            committed

.claude/skills/     → AI skill definitions     committed, update as needed
```
