# docs/agents/

Working documents for AI-assisted development on Bawbel Scanner.
These are living files used during development sessions, not user documentation.

---

## Structure

```
docs/agents/
├── prds/           Product Requirements Documents
│   ├── prd-NN-[slug].md        The PRD spec
│   └── prd-NN-tasks.md         Vertical task slices for the PRD
└── handoffs/       Session handoff notes  ← gitignored
    └── YYYY-MM-DD-HHMM.md
```

---

## PRDs

A PRD is created by the `/to-prd` skill after a `/grill-with-docs` session.
Each PRD is linked to one or more GitHub issues.

Naming: `prd-NN-[slug].md` where NN matches the primary GitHub issue number.

**Active PRDs:**

| File | Issues | Status |
|---|---|---|
| prd-02-evidence-confidence-metadata.md | #69 #70 #71 | Ready |

---

## Handoffs

Session handoff notes created by the `/handoff` skill.
Used to resume work cleanly across sessions without re-reading conversation history.

**Gitignored.** These are personal working notes, not committed.

Your `.gitignore` should contain:
```
docs/agents/handoffs/
```

If you need to hand off to another contributor, write a proper GitHub issue
or update the relevant PRD instead.

---

## How to use these files

**Starting a session:**
```bash
ls docs/agents/handoffs/ | sort | tail -1   # find most recent handoff
cat docs/agents/handoffs/<latest>.md         # read it
pytest tests/ -q                             # confirm green before touching code
```

**Ending a session:**
Use the `/handoff` skill to generate `docs/agents/handoffs/YYYY-MM-DD-HHMM.md`.

**Starting a new PRD:**
1. Run `/grill-with-docs` to design the feature
2. Run `/to-prd` to create `docs/agents/prds/prd-NN-[slug].md`
3. Run `/to-issues` to create GitHub issues from the PRD
4. Run `/prd-to-issues` (or create manually) `docs/agents/prds/prd-NN-tasks.md`
