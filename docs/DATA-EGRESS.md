# What leaves the machine

Read from the code of `origin/develop` at commit `0ddf560` and checked by runs on 2026-11-26. Each entry says how it was checked:

- **VERIFIED**: a run showed it. The run is named.
- **CODE**: read from the code and not run.
- **NOT RUN**: a run was not possible here. Nothing is claimed beyond what the code says.

No claim is made for an engine or a command that was not tested. A statement about an optional engine describes the version of that engine named in the entry.

## Summary

| Path | What leaves the machine | Checked |
|---|---|---|
| The core scan: `scan`, `report`, `creds` and `chain` with the pattern engine | Nothing | VERIFIED |
| YARA and Magika, which run inside the scanner's process | Nothing. No network system call was made by the whole process tree | VERIFIED |
| Semgrep, a separate command line the scanner starts | The scanner sends it nothing and does not turn its own requests off (issue #209). With default settings Semgrep looks up `semgrep.dev`, which is its version check. If the caller is logged in to Semgrep, or has `SEMGREP_SEND_METRICS=on`, it also tries `metrics.semgrep.dev`. What it would have sent was not observed | VERIFIED (the attempts), NOT RUN (the content) |
| Importing `litellm`, which the LLM stage, the meta-analyzer and `bawbel version` do when it is installed | A request for a public file, its model price list, from `raw.githubusercontent.com`. No file content or path | VERIFIED |
| The LLM stage | The whole file content, to the model provider you configure | VERIFIED with a stand-in for the provider library, NOT RUN against a provider |
| The meta-analyzer (false-positive filter) | The file name, the absolute path of the file's directory, and for each reviewed finding its details and the lines around it, to the same provider. `BAWBEL_LLM_ENABLED=false` does not stop it | VERIFIED with a stand-in |
| The sandbox stage | Not run. The code can pull a container image from a registry and runs the content in a container | CODE, NOT RUN |
| `scan-server-card`, `ssc` and `conform` | A request to the URL, or to the MCP registry, that you name | CODE, NOT RUN |
| The opt-in false-positive signal | Five fields, only to a URL you set, only from `bawbel accept` | CODE and VERIFIED that nothing is sent without the URL |

## How each path was checked

- **A guard.** `tests/unit/test_no_network.py` writes a `sitecustomize` module that makes `socket.connect`, `connect_ex`, `sendto`, `sendmsg`, `create_connection`, `getaddrinfo` and `gethostbyname` raise, and starts Python with it, so a child process is covered too. A control shows it stops a real attempt and a lookup in a child process. Under it, `scan` (JSON, text and SARIF), `report`, `creds` and `chain` ran on the repository's fixtures and finished without an attempt.
- **A connection logger.** A `sitecustomize` that logged and refused each attempt, with `docker run --network none` as well, so nothing could leave. It sees only Python code.
- **strace.** `strace -f -e trace=network` over the whole process tree, including native code, in a container with `--network none`, so a `connect` shows as a failed attempt and nothing leaves. The container was a scratch image with `strace` added.
- **No network at all.** `docker run --network none` for 149 fixtures with the pattern engine, with YARA, and with Semgrep (settings below). Every run exited 0 and every output was read.
- **A stand-in for the provider library.** A module named `litellm` that records the request and raises, so nothing is sent. It shows what each LLM path would send.

## The pattern engine, YARA and Magika

Nothing leaves the machine. VERIFIED: the guard and the logger above, and `strace` over a scan of 25 fixtures with the pattern engine, YARA and Magika 1.0.3 together, which made no network system call at all (not one `socket` or `connect`). Magika's model is therefore local at that version.

## Semgrep

The scanner starts `semgrep --config <a local rule file> --json --quiet <a temporary copy of the text>`. It passes no `--metrics` or `--disable-version-check` option, sets no Semgrep environment variable, and gives the child process the caller's whole environment, so a Semgrep login or a `SEMGREP_SEND_METRICS` setting of the caller reaches it. This is a defect against the rule that Semgrep runs with metrics off and no login: issue #209.

What Semgrep 1.186.0 tried to reach, with `--network none` and a logger that records each name lookup and connection attempt of the process (attempts only, so what it would have sent was not observed; VERIFIED):

| How Semgrep was started | Attempts | Hosts |
|---|---|---|
| as the scanner starts it, no login | 4 | `semgrep.dev` |
| `--metrics=off` only | 4 | `semgrep.dev` |
| `--disable-version-check` only | 0 | none |
| both flags | 0 | none |
| `SEMGREP_SEND_METRICS=off` only | 4 | `semgrep.dev` |
| `SEMGREP_ENABLE_VERSION_CHECK=0` only | 0 | none |
| both settings in the environment | 0 | none |
| caller logged in (a dummy token), as the scanner starts it | 5 | `metrics.semgrep.dev`, `semgrep.dev` |
| caller logged in, with both flags | 0 | none |
| caller has `SEMGREP_SEND_METRICS=on`, as the scanner starts it | 5 | `metrics.semgrep.dev`, `semgrep.dev` |
| caller has `SEMGREP_SEND_METRICS=on`, with both flags | 0 | none |

So the lookups of a default scan with no login are the version check, not metrics. Semgrep's own help says that with the option absent, metrics are sent when the `--config` value pulls from the Semgrep server or the user is logged in, and always when set to `on`. The two flags on the command line closed every case above. In the environment, the two settings closed the default case, and the login and `on` cases were measured only with the flags.

- Earlier runs, with default settings and a new home directory, gave the same lookups: `strace` over one scan showed eight `connect` calls to the DNS resolver on port 53, each failing with `ENETUNREACH`, and with the two settings in the environment, no `connect` to an internet address (only local sockets), and Semgrep ran (VERIFIED).
- With default settings and no network, the Semgrep engine did not run: the result lists it as degraded with the reason `timeout` and the error code `E013` (VERIFIED). A scan with no network therefore needs those two settings for Semgrep to run.
- `strace` followed Semgrep's native binary as well, so the result above covers it.

## The LLM stage

When a model is configured (`BAWBEL_LLM_MODEL`, or a provider key in the environment), the `litellm` library is installed and `BAWBEL_LLM_ENABLED` is not `false`, the scanner sends one request per file: a system prompt and the file's text, after fenced code is removed and suppression comments are masked, between two markers. The request has a model name, a token limit and a timeout, and no file path. The destination is the provider that `litellm` resolves for the model (CODE). VERIFIED with a stand-in: one request, carrying the file text. With the real library, a dummy key and the network disabled, the logger saw the library try `api.anthropic.com` on port 443, which is the default for an Anthropic key. NOT RUN against a provider.

## The meta-analyzer

The meta-analyzer reviews findings whose confidence is between 0.35 and 0.80 after the false-positive pipeline. It runs when `BAWBEL_META_ANALYZER_ENABLED` is not `false`, `litellm` is installed, and a provider key or `BAWBEL_LLM_MODEL` is set. **It does not read `BAWBEL_LLM_ENABLED`.** With that setting at `false` and a provider key set, one of 149 fixtures made a request in the stand-in run, and `BAWBEL_META_ANALYZER_ENABLED=false` made it zero (VERIFIED).

The request, for each file, has: the file's name, the content type label, **the absolute path of the file's directory**, the number of lines, and for each reviewed finding its rule id, AVE id, title, severity, score, engine, line, the matched text, the confidence, and up to five lines of the file around it. VERIFIED with a stand-in; NOT RUN against a provider.

## Importing `litellm`

Importing `litellm` makes it try to fetch its model price list, a public file, from `https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json`, and fall back to a local copy when it cannot (VERIFIED: its own warning names the URL, and `strace` showed lookups through the DNS resolver, with the network disabled). Nothing from your files is in that request. The import happens when the LLM stage or the meta-analyzer starts, and in `bawbel version` whenever `litellm` is installed, **before any key is checked**. With `LITELLM_LOCAL_MODEL_COST_MAP=True` in the environment there was no warning and no connection attempt (VERIFIED).

## The sandbox stage

Off unless `BAWBEL_SANDBOX_ENABLED=true`. Read from `scanner/engines/sandbox_engine.py` (CODE, NOT RUN: no Docker daemon was driven by the scanner here): it checks for a local image, otherwise runs `docker pull` for `bawbel/sandbox:latest` from the registry, otherwise builds one from the bundled Dockerfile. The content is passed into a container whose network is `none` unless `BAWBEL_SANDBOX_NETWORK` says otherwise. An image pull sends the image name and the usual registry requests.

## Commands that fetch by design

- `scan-server-card` and `ssc` fetch a server card from the URL given (`scanner/fetcher.py`). The request carries the scanner's name and version as its user agent (CODE, NOT RUN).
- `conform` takes a URL, or a server name that it looks up in the MCP registry at `https://registry.modelcontextprotocol.io` unless `BAWBEL_MCP_REGISTRY_URL` is set (`scanner/cli/cmd_conform.py`) (CODE, NOT RUN).
- `bawbel version` runs `semgrep --version` and `docker info` on the machine and imports `litellm` if it is installed, to report whether each is there. The import is the request described under "Importing `litellm`".

## The opt-in false-positive signal

`bawbel accept` can send `ave_id`, `rule_id`, `engine`, a confidence and a hash of the matched text to a URL, as a `POST`, with the scanner's user agent. It does so only when the accepted entry asks for it and `BAWBEL_PIRANHA_URL` is set to an http or https URL. The default is unset, and nothing is sent (CODE). VERIFIED that with the URL unset the function returns without opening a connection, and that no other command calls it (`tests/unit/test_no_network.py`).

## Settings that close each path

| To stop | Set |
|---|---|
| the LLM stage | `BAWBEL_LLM_ENABLED=false`, or no model and no provider key |
| the meta-analyzer | `BAWBEL_META_ANALYZER_ENABLED=false`, or no provider key and no `BAWBEL_LLM_MODEL`, or `litellm` not installed |
| Semgrep's own requests | `--metrics=off` and `--disable-version-check` on its command line, which the scanner does not pass (issue #209); `SEMGREP_ENABLE_VERSION_CHECK=0` stops the lookups of a default scan. Only the flags were measured to close the login and `SEMGREP_SEND_METRICS=on` cases |
| the sandbox stage | leave `BAWBEL_SANDBOX_ENABLED` unset |
| the signal | leave `BAWBEL_PIRANHA_URL` unset |
| `litellm`'s request for its price list | `LITELLM_LOCAL_MODEL_COST_MAP=True` in the environment of the scan |

## Where the code can reach the network

A test lists every module in `scanner/` that imports a network library, so a new one fails until this document is updated:

| Module | Library | For |
|---|---|---|
| `scanner/engines/llm_engine.py` | `litellm` | the LLM stage |
| `scanner/engines/meta_analyzer.py` | `litellm` | the meta-analyzer |
| `scanner/fetcher.py` | `urllib.request` | `scan-server-card` and `ssc` |
| `scanner/cli/cmd_conform.py` | `urllib.request` | `conform` |
| `scanner/suppression/justified.py` | `urllib.request` | the opt-in signal |
| `scanner/cli/cmd_version.py` | `litellm` | `bawbel version`, an import only |

The sandbox stage and Semgrep reach the network through other programs (`docker`, `semgrep`), which the test cannot list.

## Not verified

- Any real provider, Docker registry, MCP server or registry. Only a stand-in, the code, and the guard.
- What Semgrep and `litellm` send when their requests are allowed. Only the attempts were observed.
- Windows and macOS.
- Other versions of Semgrep, Magika, YARA and `litellm` than the ones in the runs.
