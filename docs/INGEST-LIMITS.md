# Ingest limits

What stops a hostile file from stalling or crashing a scan, what does not, and what was measured. Measured on `origin/develop` at commit `0ddf560` with the fix from issue 198, Python 3.12.13, on 2026-11-26, pattern engine unless stated. The scanner reads single files. It does not open archives, so there is no archive size or member count limit.

## Limits that exist

| Limit | Default | Setting | What happens |
|---|---|---|---|
| File size | 10 MB | `BAWBEL_MAX_FILE_SIZE_MB` | The file is not read. Error `E006` |
| Not a regular file (a named pipe, a device) | none | none | Not read. Error `E004`. A named pipe called `SKILL.md` did not block |
| Symlink | none | none | Not followed or read. Error `E005`. A symlink loop in a tree is not followed |
| Semgrep process | 30 s | `BAWBEL_SCAN_TIMEOUT_SEC` | The engine is reported degraded (`E013`) |
| LLM call, sandbox, HTTP fetch | 60 s, 120 s, 10 s | `BAWBEL_LLM_TIMEOUT_SEC`, `BAWBEL_SANDBOX_TIMEOUT_SEC`, `BAWBEL_HTTP_TIMEOUT_SEC` | The stage is reported degraded |
| Text kept in a finding | 80 characters | none | The matched text is cut |

## Limits that do not exist

- **Line length and total scan time for the pattern engine and YARA.** Every pattern runs on every line with no time budget. A limit on line length would hide the text after the cut, so none was added. This is a decision for the maintainer.
- **Directory depth and file count.** A tree of 300 nested directories was listed in under 0.1 s. A very large file count was not measured.

## What was measured

- **A quadratic pattern, now fixed.** One pattern of `bawbel-hardcoded-credential` (AVE-2026-00047) took 0.19 s at 10,000 characters, 0.75 s at 20,000, 3.1 s at 40,000 and 13.5 s at 80,000 on a line of letters: each doubling quadrupled it. A scan of one 5 MB line had not returned after 216 s. The pattern now starts only at the start of a word. On 18,857 matching strings built to exercise it, and on 57 more, the old and new patterns gave the same matched span in every case. At 80,000 characters it takes 0.001 s.
- **Every pattern of every rule, after the fix.** On eleven adversarial single lines of 200,000 characters the slowest single search was 13 ms.
- **The cost that remains is linear.** One 5 MB line of letters: 17.3 s. One 10 MB line: 43.6 s. A 5 MB file of 262,000 short lines: 30.2 s. About 3.4 seconds per megabyte on this machine, almost all of it in the regular expression searches. A file at the size limit can take up to about 45 s.
- **YARA.** Five megabytes of `a`, of spaces, of `ignore all ` and of `x | ` took 0.04 s or less. Five megabytes of `curl ` repeated took 10.6 s, because the fetch-then-pipe expression looks up to 300 characters ahead from each `curl`. Linear in size, with a large constant.
- **Odd bytes.** NUL bytes and invalid UTF-8 are scanned without an error.

## Tests

`tests/unit/test_ingest_limits.py`: every pattern of every rule on adversarial lines, with a limit the old pattern fails; the credential pattern is linear and matches what the old one did; named pipe, symlink, symlink loop, deep tree, NUL bytes, invalid UTF-8, a directory named like a skill and an oversize file; and a seeded fuzz test (a fixed seed, the standard library only) that `scan()` never raises.

## Not verified

- Semgrep on adversarial input, and the LLM stage. Their limits are timeouts.
- Archives (not supported), Windows and macOS, and a tree with a very large number of files.
