# File enumeration: which files a directory scan never reads

Report only. Nothing in this pull request changes what the scanner reads, prints or exits with.
It concerns public issue 132 and was measured on `origin/develop` at commit `e1cb2c5` on 2026-11-25.
Choosing among options A, B and C below is the maintainer's decision, and none is implemented here.

## Summary

- A directory scan reads only files whose extension is `.md`, `.json`, `.yaml`, `.yml` or `.txt`. The collector decides this before any engine runs, so for every other file type no engine sees the file. Measured on 17 file types: the sentence below is flagged in the `.md` file and in none of the others.
- Handed the same files one at a time, `scan()` reads them, and the pattern, YARA and Semgrep engines match the sentence in all 17 of them, including inside a `.pyc`. So the gap is in file enumeration, not in what the text engines can match.
- The Magika engine would not close it as written. Its list of dangerous types uses the keys `python_pyc`, `pe32`, `pe64` and `jsp`. Magika 1.0.3 and 0.6.1 have no such labels, and the 0.5.1 config has no `python_pyc`, `pe32` or `pe64` (a `.pyc` is labelled `pythonbytecode`, a Windows executable `pebin`). So a `.pyc` handed to `scan()` gets no Magika finding either.
- With Magika installed, a `.sh` or `.bat` file handed to `scan()` gets one HIGH finding ("disguised as skill file") and the text engines are skipped for it. That is a false-positive cost for options A and B on any skill that ships a shell script.
- Output says nothing about files that were not read. A directory with 2 unread files prints the same summary as a directory with none. A specification for fields that say so is in section 5.
- Options A, B and C are costed in section 6. Section 7 describes the test that fails today and what turns it green.

## 1. Reproduction on develop

The files hold one prose sentence, `ignore all previous instructions`, which the pattern rules flag in a `.md` file. The `.pyc` is compiled by `py_compile` with `PycInvalidationMode.UNCHECKED_HASH` from a source that only has a docstring. Nothing was executed and no payload was built. Engines that ran: pattern and YARA (core install plus `yara-python`). The command is `python -m scanner.cli scan`, which is what the `bawbel` command runs.

```text
$ find skill -type f | sort
skill/SKILL.md
skill/__pycache__/extra.cpython-312.pyc
skill/extra.md
skill/extra.py
```

```text
$ bawbel scan skill
  Scanning:  skill/SKILL.md
  Findings:     0
  Scanning:  skill/extra.md
  🟠  HIGH  AVE-2026-00007
  Engine: pattern
  🟠  HIGH  AVE-2026-00002
  Engine: yara
  Risk score:   8.1 / 10  HIGH
  Findings:     2
exit=0
```

```text
$ bawbel scan skill --recursive
  Scanning:  skill/SKILL.md
  Findings:     0
  Scanning:  skill/extra.md
  🟠  HIGH  AVE-2026-00007
  Engine: pattern
  🟠  HIGH  AVE-2026-00002
  Engine: yara
  Risk score:   8.1 / 10  HIGH
  Findings:     2
exit=0
```

```text
$ bawbel scan skill/extra.py
  Scanning:  skill/extra.py
  🟠  HIGH  AVE-2026-00007
  Engine: pattern
  🟠  HIGH  AVE-2026-00002
  Engine: yara
  Risk score:   8.1 / 10  HIGH
  Findings:     2
exit=0
```

```text
$ bawbel scan skill/__pycache__/extra.cpython-312.pyc
  Scanning:  skill/__pycache__/extra.cpython-312.pyc
  🟠  HIGH  AVE-2026-00007
  Engine: pattern
  🟠  HIGH  AVE-2026-00002
  Engine: yara
  Risk score:   8.1 / 10  HIGH
  Findings:     2
exit=0
```

The exit code is 0 in all four because no `--fail-on-severity` was given. In the recursive scan, `extra.md` is flagged HIGH and the `.py` and `.pyc` next to it are not listed at all. Handed to `scan()` directly, both are flagged. Without `--recursive` the scan stops at the top level, so `__pycache__/` is never entered.

## 2. What the collector reads

`scanner/cli/shared/utils.py`, `collect_files`, lists files by glob on five extensions and returns them sorted. Measured here on Linux, where glob matching is case sensitive:

| Case | Listed |
|---|---|
| `.md`, `.json`, `.yaml`, `.yml`, `.txt` | yes |
| `.MD` (upper case) | no |
| `.markdown` | no |
| `.toml` | no |
| a file with no extension (`run`, with a shebang) | no |

`scan()` itself lower-cases the extension when it picks the component type, so `extra.MD` is typed `skill` when handed over directly. Behaviour on macOS and Windows, where the file system can be case insensitive, was not measured.

## 3. File types and engines

Every file below was written with the same sentence and built by the harness described in section 8. "Handed to `scan()`" means `scan(path, no_ignore=True)`, the audit mode, so the false-positive pipeline does not hide what an engine matched.

| File type | Listed by `collect_files` (recursive / not) | pattern, YARA, Semgrep on the file when handed to `scan()` | Magika label (score) | Magika finding |
|---|---|---|---|---|
| .md (control) | yes / yes | all three match | markdown (0.975) | none |
| .MD upper case | no / no | all three match | markdown (0.975) | none |
| .markdown | no / no | all three match | markdown (0.975) | none |
| .toml | no / no | all three match | txt (0.443) | none |
| .py | no / no | all three match | python (0.998) | none |
| .js | no / no | all three match | javascript (0.747) | none |
| .mjs | no / no | all three match | javascript (0.806) | none |
| .ts | no / no | all three match | typescript (0.991) | none |
| .sh | no / no | all three match | shell (0.943) | content-type-dangerous HIGH |
| .ps1 | no / no | all three match | txt (0.461) | none |
| .bat | no / no | all three match | batch (0.999) | content-type-dangerous HIGH |
| .rb | no / no | all three match | txt (0.359) | none |
| .php | no / no | all three match | php (0.533) | none |
| (no extension, shebang) | no / no | all three match | shell (0.943) | content-type-dangerous HIGH |
| .pyc (unchecked-hash) | no / no | all three match | pythonbytecode (0.986) | none |
| .pyc (timestamp) | no / no | all three match | pythonbytecode (0.993) | none |
| .pyc (realistic size, unchecked-hash) | no / no | all three match | pythonbytecode (1.0) | none |

How to read it:

- Pattern, YARA and Semgrep are called by themselves on the content `scan()` reads, so deduplication inside `scan()` cannot hide which engine matched. YARA and Semgrep write that content to a temporary file first (Semgrep always as a `.md` file), so the original extension does not change what they match.
- Where Magika says `shell` or `batch` with a score above 0.75, the engine reports `bawbel-content-type-dangerous` at HIGH. A score below 0.75 is dropped by the engine, which is why a short `.ps1`, `.rb` or `.php` file (ps1 0.461, rb 0.359, php 0.533) gets none. The scores are for these small files and say nothing about larger ones.
- The `.pyc` gets no Magika finding at either size tested. The realistic-size case is 21789 bytes, compiled from `scanner/utils.py` with one docstring line added: Magika labels it `pythonbytecode` with score 1.0, and the engine's key for bytecode is `python_pyc`.
- Pattern matched the sentence inside the `.pyc` because a docstring is stored in a `.pyc` as readable text. This says nothing about code that builds its strings at run time.

What each engine does with these files in a scan:

| File type | Directory scan, `--recursive`: finding on this file | `scan()` on the file, no Magika: engines that ran | `scan()` on the file, Magika installed: engines that ran |
|---|---|---|---|
| .md (control) | yes | pattern, semgrep, yara | magika, pattern, semgrep, yara |
| .MD upper case | no | pattern, semgrep, yara | magika, pattern, semgrep, yara |
| .markdown | no | pattern, semgrep, yara | magika, pattern, semgrep, yara |
| .toml | no | pattern, semgrep, yara | magika, pattern, semgrep, yara |
| .py | no | pattern, semgrep, yara | magika, pattern, semgrep, yara |
| .js | no | pattern, semgrep, yara | magika, pattern, semgrep, yara |
| .mjs | no | pattern, semgrep, yara | magika, pattern, semgrep, yara |
| .ts | no | pattern, semgrep, yara | magika, pattern, semgrep, yara |
| .sh | no | pattern, semgrep, yara | magika |
| .ps1 | no | pattern, semgrep, yara | magika, pattern, semgrep, yara |
| .bat | no | pattern, semgrep, yara | magika |
| .rb | no | pattern, semgrep, yara | magika, pattern, semgrep, yara |
| .php | no | pattern, semgrep, yara | magika, pattern, semgrep, yara |
| (no extension, shebang) | no | pattern, semgrep, yara | magika |
| .pyc (unchecked-hash) | no | pattern, semgrep, yara | magika, pattern, semgrep, yara |
| .pyc (timestamp) | no | pattern, semgrep, yara | magika, pattern, semgrep, yara |

- In a directory scan no engine runs on any file type that is not listed. The Magika engine in particular is not reached, which matches the public report.
- Handed over directly with Magika installed, `.sh`, `.bat` and the extension-less script get Magika's finding and the text engines are skipped for them. The sentence in those files is then not matched by any text engine.
- The LLM engine did not run (no key), and the sandbox stage was off. The sandbox stage needs Docker, is off by default, and only receives files that `scan()` was given. What either would do with these file types was not measured.

**The false-positive pipeline.** In normal mode (without `--no-ignore`), the pattern match on a `#` comment line in a `.sh` or `.rb` file is suppressed as `low_confidence (0.35 < 0.60 [unknown profile])`, and only the YARA finding remains. A core install without YARA would show nothing for that line. The strict xfail test avoids this by not putting the sentence on a `#` line in those files, so that it measures enumeration only. Whoever implements option B must decide how the pipeline treats source files.

## 4. Which extensions

The file types measured above start from `.py .pyc .js .mjs .ts .sh .ps1 .bat .rb`. The evidence in this repository for the file types a component can carry:

- `scanner/engines/magika_engine.py` expects `.py`, `.js`, `.ts` and `.toml` among skill-adjacent files, and names `elf`, `pe32`, `pe64`, `python_pyc`, `php`, `jsp`, `shell`, `batch`, `powershell` and `pickle` as dangerous content. So the project already treats executable types, bytecode, Windows binaries, PHP and pickles as things that can be present.
- `.MD`, `.markdown` and `.toml` are text types the collector does not list (section 2).

No other extension is claimed. There is no evidence in this repository for `.cjs`, `.jsx`, `.tsx`, `.pl`, `.lua`, `.so`, `.dll`, `.exe`, `.wasm` or archives, and they are not in the tables. Native binaries and archives are a third category (neither text nor bytecode) that none of the three options below addresses.

## 5. Specification: files not scanned (not implemented)

Goal: a result with no findings must not read as full coverage of the directory. Additive fields only. This section specifies and does not implement.

**Definition.** For a directory scan, a file is skipped when it is a regular file under the scanned directory that `collect_files` did not return, excluding anything under a `.git` directory. Without `--recursive`, files in subdirectories count as skipped with reason `not_recursive`, because they were not entered. A file named on the command line is never skipped. Open: whether files ignored by `.bawbelignore` count (they are suppressed findings today, not unlisted files), and whether `node_modules` and similar directories are excluded.

**Extension key.** The lower-cased last suffix with its dot (`.py`, `.pyc`, `.gz` for `.tar.gz`), or `(none)` when there is none (this includes names such as `.env`). Not specified: a cap on the number of keys.

**JSON.** One new key on each result of a directory scan, `coverage`, the same object on every result of that scan. The output is a list of per-file results and has no place for a run-level object without wrapping it, which would change the shape and is therefore not proposed. A single-file scan gets `"coverage": null`.

```json
"coverage": {
  "directory_scan": true,
  "files_scanned": 2,
  "files_skipped": 2,
  "skipped_by_extension": {".pyc": 1, ".py": 1},
  "skipped_by_reason": {"extension_not_scanned": 2}
}
```

The values above are what the rule gives for the directory in section 1.

**SARIF.** `runs[].invocations[].properties.coverage` carries the same object, and one entry in `toolExecutionNotifications` with `descriptor.id` `bawbel-files-skipped`, level `warning`, and a message such as `2 file(s) were not scanned: .pyc 1, .py 1`. This follows how `bawbel-engine-degraded` is reported today.

**Text.** One line after the last result, printed only when the count is above zero:

```text
Not scanned: 2 file(s) (.pyc 1, .py 1). A result with no findings covers only the files that were read.
```

**Exit codes.** Unchanged. No new exit code.

**Contract block.**

```text
Fields added:    result.coverage (JSON, per file result of a directory scan, null otherwise)
                 runs[].invocations[].properties.coverage and one toolExecutionNotifications
                 entry with descriptor.id bawbel-files-skipped (SARIF)
                 one "Not scanned:" line in the text summary
Fields renamed:  none
Fields removed:  none
```

**Cost.** One walk of the directory tree. Measured: 2.4 ms to list all 321 entries of this repository's tree. Not measured: a tree with hundreds of thousands of entries.

## 6. Options and measured costs

The three options are those named in issue 177: **A** flag the presence of precompiled bytecode (`.pyc`, `__pycache__`) and other executable files as a finding without analysing them, **B** also run the existing text engines on source files, **C** analyse bytecode.

What the existing tests can and cannot show. No file under `tests/fixtures/` has an executable-type extension and no `.pyc` is committed (both counted with `git ls-tree` on `origin/develop`, result 0). So the suite cannot show the false-positive cost of A or B. With a prototype of B in a scratch copy (the collector also listing `.py .js .mjs .ts .sh .ps1 .bat .rb`), the core suite gave `860 passed, 17 skipped, 2 xfailed`, identical to `develop`. The costs below were measured on this repository's own source files instead, and on the maintainer's workspace.

| | A: flag presence | B: text engines on source files | C: analyse bytecode |
|---|---|---|---|
| Files it would add on this repository (scanner/, scripts/, tests/) | 117 source files (scanner/ 65, scripts/ 10, tests/ 42), every one would be flagged by presence | the same 117 files | none of the 117: it concerns `.pyc` only |
| False positives on those files | a finding on all 117, by definition | 27 of 117 files get at least one finding (121 findings) with pattern and YARA, because the rule definitions and tests contain the attack phrases the rules look for. With Magika installed, 4 of 4 `.sh` files get a HIGH "disguised as skill file" finding and are not text-scanned | not measured |
| On a workspace sample (counts only) | 16 of 139 distinct skill directories on one developer workspace carry at least one executable-type file below them | same 16 | not measured |
| Time | 2.4 ms to walk 321 entries, no engine work | pattern and YARA: 8.3 s for the 117 files. Semgrep adds 3089 to 3639 ms per file when it is installed, so about 361 to 426 s for the same files. Pattern alone: up to 2 ms for a file of about 100 bytes, 118 ms for a 21789 byte `.pyc` | pulling string constants and names out of 65 `.pyc` files (433156 bytes, compiled from `scanner/`) took 4 ms in total with the standard library. A real analysis of what the code does was not measured |
| What it leaves open (reasoning, not tested) | code in a type that is not on the list, native binaries, archives, and anything fetched after install. It cannot tell a bundled helper script from a hostile one | code that builds its text at run time, text in an encoding the rules do not match, `.pyc` (not in B), native binaries. The text rules' own limits apply (see `docs/LIMITATIONS.md`) | native extensions, strings built at run time, a payload fetched after install |
| Other cost | needs a rule for what counts as executable and a decision on `__pycache__`. Python writes it when modules are imported: running the scanner on the scratch copy of this repository created 58 `.pyc` files under `scanner/` and 1 under `scripts/`, none of them committed | the false-positive pipeline lowers the confidence of matches in file types without a profile (section 3), so B also needs profile decisions. The sandbox stage is unaffected | bytecode is version specific: a `.pyc` compiled by Python 3.14 could not be loaded by 3.12's `marshal` (`ValueError: bad marshal data (unknown type code)`), while a trivial 3.14 file did load. Loading untrusted bytecode with `marshal` is a risk of its own that this report did not test |

Notes on the table:

- The 117 files are this scanner's own source and tests, which contain the attack phrases by design. They show that B produces findings on a code base full of rule text. They are not an estimate of the rate on skills written by others.
- The workspace sample is 16 of 139 skill directories (distinct `SKILL.md` content, counted with `os.walk`, executable-type files only counted by extension). It is one developer workspace, mostly workflow skills that are text only, so it is not a measure of skills in general.
- "What it leaves open" is reasoning from the measurements above. No bypass was built to test it.
- There is a corpus record for this class. `AVE-2026-00075`, in the corpus the README pins, is titled "Bytecode poisoning: compiled .pyc cache diverges from its own reviewed .py source" (layer `content`). No rule in `scanner/` cites it (`git grep AVE-2026-00075 -- scanner` on `origin/develop` finds nothing). A rule is a separate decision from the three options.

## 7. The strict xfail

`tests/test_unscanned_file_types.py` builds one skill directory, scans it once with `bawbel scan DIR --recursive --format json` in a subprocess with the LLM and sandbox stages off, and checks each file:

- an anchor that passes today: the sentence in `extra.md` is flagged, so a broken scan cannot make a miss look expected;
- ten cases marked `xfail(strict=True, raises=AssertionError)`: the sentence in `.py`, `.js`, `.mjs`, `.ts`, `.sh`, `.ps1`, `.bat`, `.rb` files and in two `.pyc` files (one `UNCHECKED_HASH`, one timestamp). Each asserts that a finding is attached to that file, from any engine or rule.

On `develop`: `2 passed, 10 xfailed`. With the option B prototype above, the eight source cases fail as strict `XPASS` and the two `.pyc` cases stay expected failures, which shows the test turns red when the gap closes and that B would not close the `.pyc` cases. With `--runxfail` a case fails with `AssertionError: ... was not scanned. Scanned: ['SKILL.md', 'extra.md']`, so the reason is the enumeration.

The assertion does not prefer an option: flagging presence, running text engines, or analysing bytecode would each satisfy it. When the maintainer chooses, the cases the choice does not cover are removed or changed in the same pull request.

## 8. How this was measured

Scratch directories, throwaway containers, `origin/develop` exported with `git archive`. Python 3.12.13, yara-python 4.5.4, Semgrep 1.186.0, Magika 1.0.3 for the measurements, and 0.5.1 and 0.6.1 for the label names only. The measurement scripts are not committed. Each reported number comes from their output files:

- harness 1 builds one directory per file type and records what `collect_files` lists and what `scan()` does when handed the file (17 types);
- harness 2 calls each engine alone on the content `scan()` reads;
- harness 3 counts the files each option would touch in `scanner/`, `scripts/`, `tests/` and `docs/` and runs the existing engines on them (Semgrep excluded for time, timed separately in harness 2);
- the prototype of B is a one-line change to the extension list in a scratch copy.

## 9. Not verified

- macOS and Windows behaviour, including case-insensitive file systems.
- The LLM stage and the sandbox stage on any of these file types.
- Magika 0.5.1: its config file was searched for the key names `python_pyc`, `pythonbytecode`, `pebin`, `pe32` and `pe64` only. The package could not be imported there (a missing dependency), so its label list was not read and `jsp` was not checked.
- Larger files than the ones above for Magika's score.
- Whether a payload built the way the public issue describes behaves as reported. The reporter's proof of concept was not run and no payload was built.
- Semgrep's per-file time on a file the engine would not reach through the collector today.
