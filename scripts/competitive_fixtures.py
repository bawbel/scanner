#!/usr/bin/env python3
"""Build the harmless fixtures for the capability matrix. Read only on its inputs.

Standard library only. Writes one skill directory per fixture, each with a SKILL.md, and a
manifest.json that says where each fixture came from.

    python3 -I scripts/competitive_fixtures.py --corpus CORPUS.json --repo . --out DIR

Two sources:

  - the example_patterns of the active records in the AVE corpus, one example per SKILL.md, under
    the same minimal frontmatter for every tool (the corpus file is an input and is not copied
    into the repository)
  - this repository's own test fixtures: the golden skill, and the skill whose attack text sits
    inside suppression comments on purpose (it is not a benign sample)

Nothing here is executed by anyone. The text is only read by the scanners.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

FRONTMATTER = (
    "---\nname: {name}\ndescription: A fixture for a scanner comparison. It does nothing.\n---\n\n"
)

REPO_FIXTURES = (
    ("repo-golden-skill", "tests/fixtures/skills/malicious/malicious_skill.md"),
    ("repo-suppression-skill", "tests/fixtures/skills/clean/self_referential_suppression.md"),
)


def write_fixture(out: Path, fixture_id: str, body: str, with_frontmatter: bool) -> None:
    directory = out / fixture_id
    directory.mkdir(parents=True)
    text = (FRONTMATTER.format(name=fixture_id) if with_frontmatter else "") + body
    (directory / "SKILL.md").write_text(
        text if text.endswith("\n") else text + "\n", encoding="utf-8"
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    raw = Path(args.corpus).read_bytes()
    records = json.loads(raw)
    out = Path(args.out)
    out.mkdir(parents=True)
    manifest = []

    for record in sorted(records, key=lambda r: r["ave_id"]):
        if record.get("status") != "active":
            continue
        examples = record.get("example_patterns")
        if not isinstance(examples, list):
            continue
        for index, example in enumerate(examples):
            fixture_id = f"{record['ave_id'].lower()}-{index}"
            write_fixture(out, fixture_id, str(example), with_frontmatter=True)
            manifest.append(
                {
                    "fixture": fixture_id,
                    "source": "ave-example",
                    "ave_id": record["ave_id"],
                    "layer": record.get("detection_layer"),
                    "stage": record.get("detection_stage"),
                    "index": index,
                }
            )

    for fixture_id, relative in REPO_FIXTURES:
        body = (Path(args.repo) / relative).read_text(encoding="utf-8")
        write_fixture(out, fixture_id, body, with_frontmatter=not body.startswith("---"))
        manifest.append({"fixture": fixture_id, "source": "repo", "path": relative})

    (out / "manifest.json").write_text(
        json.dumps(
            {
                "corpus_sha256": hashlib.sha256(raw).hexdigest(),
                "fixtures": manifest,
            },
            indent=1,
        ),
        encoding="utf-8",
    )
    print(
        f"wrote {len(manifest)} fixtures to {out} (corpus sha256 {hashlib.sha256(raw).hexdigest()})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
