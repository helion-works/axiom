# FP_BASELINE.md — false positives on servers Axiom's authors did not write

**Scanner:** Axiom at commit `5f3d93b` (the Phase 4 starting commit: rename + E.1 TypeScript parsing + Surface Map). **No rule or severity was changed while these numbers were taken.** The "after" numbers (Part C) are in `docs/COVERAGE.md` and `LAUNCH_READINESS.md`, side by side with these.
**Date:** 2026-11-04. **Command:** `axiom scan <dir> --output json --no-ai --no-history`. Raw outputs are committed untouched under `proofs/`.
**Rule of this file:** a HIGH or CRITICAL on a healthy server is a false positive by default. Where a finding is argued to be real, the exact line is quoted. Secret *values* are never written here.

---

## A.1 Official reference servers (`modelcontextprotocol/servers`, `src/*`, cloned 2026-11-04)

Seven servers: `everything`, `filesystem`, `memory`, `sequentialthinking` (TypeScript); `fetch`, `git`, `time` (Python). Raw: `proofs/reference-servers/raw/<server>.json`.

### Totals at the starting commit

| server | lang | tools extracted | risk | critical | high | medium | low | info |
|---|---|---|---|---|---|---|---|---|
| everything | TS | 24 | critical | 6 | 41 | 5 | 0 | 0 |
| fetch | Py | 1 | critical | 0 | 43 | 0 | 0 | 1 |
| filesystem | TS | 14 | critical | 63 | 18 | 3 | 10 | 0 |
| git | Py | 12 | critical | 0 | 99 | 10 | 1 | 0 |
| memory | TS | 9 | critical | 5 | 6 | 5 | 0 | 0 |
| sequentialthinking | TS | 1 | critical | 7 | 9 | 2 | 0 | 0 |
| time | Py | 2 | critical | 0 | 20 | 0 | 0 | 1 |
| **total** | | **63** | **7/7 "critical"** | **81** | **236** | **25** | **11** | **2** |

Every reference server is rated *critical*. **All 81 CRITICAL and all 236 HIGH findings are false positives** (triage below). Tool extraction itself is right: 63 tools, every name, description and schema matches the source (E.1), and the Surface Map capability tags are sensible (`filesystem` → `fs.read`/`fs.write`, `fetch` → `net.egress`, `everything/printEnv` → `env`).

### Triage of every CRITICAL (81) and HIGH (236), grouped by rule

| rule (category) | servers | count | verdict | what matched — exact lines |
|---|---|---|---|---|
| `code_*` **sandbox_escape** CRITICAL | filesystem 61, everything 5, memory 5, sequentialthinking 5 | **76** | **FP** | the regex `symlink\|realpath\|readlink\|path\.join\([^)]*\.\.` over every source line. `filesystem/index.ts:13 import { realpathSync } from "fs";` · `path-utils.ts: return await fs.realpath(p);` · a *comment*: `// O_EXCL: an existing file or symlink fails with EEXIST, never followed.` · the error string `Access denied - symlink target outside allowed directories` (the server's own *defence*) · `version.ts:22 path.join(moduleDir, "..", "package.json")` (reading its own package.json). Resolving symlinks is how a filesystem server *prevents* escapes. |
| `poison_*_instruction_injection` **tool_poisoning** CRITICAL | filesystem 2, sequentialthinking 1 | 3 | **FP** | `create_directory`: "If the directory already exists, this operation will succeed **silently**." · `directory_tree`: "directories **always** have a children array" · `sequentialthinking`: "**You should**: 1. Start with an initial estimate of needed thoughts". Single imperative words in ordinary guidance. |
| `poison_*_priv_escalation` **tool_poisoning** CRITICAL | sequentialthinking 1 | 1 | **FP** | "Problems where the **full scope** might not be clear initially" matched `(unrestricted\|unlimited\|full)\s+(access\|permission\|control\|scope)`. |
| `toxic_combo_code_execute_*` **toxic_tool_combo** CRITICAL/HIGH | everything 2, filesystem 1 | 3 (1 CRITICAL) | **FP** | the loose capability classifier tags `read_text_file` and `trigger-long-running-operation` as *code execution* from the words "text"/"run"/"operation"; neither executes anything. |
| other `toxic_combo_*` HIGH | everything 2, fetch 1, sequentialthinking 1 | 4 | **FP** | `fetch`: "data read + external network" — it is a fetch server, that is its one job. `sequentialthinking`: "credential access + data write" from one thinking tool. `everything`: `get-*` tools tagged data-read + `trigger-*` tools tagged network. |
| `GHSA-*` **dependency_vuln** HIGH | everything 15, fetch 40, filesystem 16, git 99, memory 6, sequentialthinking 7, time 20 | **203** | **FP** | OSV is queried **without a version** (`engine.py:897`: `{"package": {"name", "ecosystem"}}`), so every advisory ever filed for the package is reported. `fetch` locks `mcp==2.3.0` (`uv.lock:722`) and gets 16 `mcp` advisories plus 16 for `requests`; `git` gets 79 for `gitpython` and 16 for `mcp`; `time` gets 16 for `mcp` and 4 for `pydantic`. Not one was checked against the locked version. |
| `live`-style **transport_security** HIGH | everything 21 | 21 | **FP** | 20× "Remote MCP server without authentication" and 1× "Session ID exposed in URL" on `transports/sse.ts` and the streamable-HTTP transport — a reference implementation of the protocol's own transports, bound to localhost (`README`: refuses non-localhost `Origin`). Static transport rules fire on the *presence* of a transport. |
| `ast_*` **credential_theft** HIGH | fetch 2 | 2 | **FP** | `server.py:350 os.environ.get(...)` / `:352 os.environ[...]` — the fetch server reads its proxy settings. Reading an env var is a capability, not theft. |
| `rugpull_add_tool_tools_list_changed` **rug_pull_primitive** HIGH | everything 1 | 1 | **FP (severity)** | `server/context.ts:71 sendToolListChanged()` — the `everything` server exists to demonstrate every protocol feature, including list-changed notifications. A mutation primitive is real information (it is in the Surface Map) but it is MEDIUM at most, not HIGH. |
| `blast_radius_estimate` **cascading_failure** HIGH | everything, filesystem, sequentialthinking | 3 | **FP (derived)** | computed from the findings above; falls with them. |

**Critical false-positive rate on the reference servers: 81 / 81 = 100 %.** High: 236 / 236. Zero true positives, which is the expected result for the official servers.

### What *should* have been reported (for the record)

- `filesystem`: `fs.read`, `fs.write` capability notes on 14 tools; `everything`: `env` (`printEnv`), `net.egress`-free; `fetch`: `net.egress`; `git`: `exec` (it shells out to `git`) — all INFO/LOW capability inventory, which the Surface Map now carries.
- `everything`: `sendToolListChanged()` and `listChanged` capability → MEDIUM mutation note.
- Dependency advisories that actually cover the locked versions (to be re-measured after Part C with version-aware OSV queries).

---

## A.3 Live false positives on a healthy local server (`127.0.0.1`, no auth)

The spec asks for `agentav live` against one *reference* server on localhost. The environment in which this phase ran did not allow third-party code to be executed (`npx @modelcontextprotocol/server-everything`, and the MCPSecBench servers), so the live target is a 50-line server written for this purpose, `tests/fixtures/healthy_http_server.py`: three harmless tools (`word_count`, `ping`, `to_upper`), one static resource, one prompt with a required argument, no instructions, served over Streamable HTTP with the official Python SDK 2.x on `127.0.0.1:3010`. It is deliberately boring. Raw: `proofs/live-localhost/raw/healthy_http_before.json`.

```
axiom live --url http://127.0.0.1:3010/mcp --output json
```

| | |
|---|---|
| status | completed, transport `streamable-http`, 3 tools, 1 resource read, 0 prompts fetched (required argument — skipped by design) |
| risk | **medium**, score 30 |
| findings | `live_127.0.0.1_3010_plain_http` **HIGH** — "Remote MCP server accessed over plain HTTP"; `live_127.0.0.1_3010_no_auth` **HIGH** — "Remote MCP server accepted an unauthenticated session" |

Exactly the noise the spec predicted. Both are **false positives on localhost** and go on the Part C list: transport findings must be scored by where the host is (public → HIGH, private range → LOW, loopback → INFO). Nothing else fired: the tool, resource and prompt text rules were clean.

---

## A.2 Registry sample (50 servers) — before, at commit `5f3d93b`

**Selection.** The official MCP Registry (`https://registry.modelcontextprotocol.io/v0/servers`, every page, `version=latest`, status `active`) listed **56,203** latest entries on 2026-11-04, **29,292** of them with a unique public GitHub repository. The API exposes no download or reference counts, so "most referenced" was approximated by GitHub stars: a pool of 400 entries was drawn uniformly at random (seed `20261104`), forks dropped, and the **25 most-starred** of the pool taken as the popular half; **25 more** were drawn uniformly at random from the rest. The list, with stars and registry names, is `proofs/registry-sample/scan_log.json`; the selection code is reproducible from the seed. Each repository was cloned at depth 1 and scanned with the scanner frozen at `5f3d93b` (a git worktree), `axiom scan <dir> --output json --no-ai --no-history`. Raw: `proofs/registry-sample/raw/NN_owner__repo.json`.

**Five repositories could not be checked out on Windows** (filenames invalid on NTFS or paths too long: `robotmcp/ros-mcp-server`, `feimacode/open-design-agent-kit`, `Aimino-Tech/opendocswork-mcp`, `SigNoz/signoz-mcp-server`, `AsoBeast/asobeast`); they appear as 0-tool "safe" rows and are **not counted** as scanned. Two more (`CorporateSmalltalkConsultingLtd/ClaudeSmalltalk`, `mambalabsdev/mcp-workplace-program-detector`) needed `core.longpaths=true` and were scanned on retry. Effective sample: **45 scanned**.

### Totals (before)

| | |
|---|---|
| servers scanned | 45 (of 50 selected) |
| rated *critical* | 36 |
| CRITICAL findings | 5,258 |
| HIGH findings | 2,943 |
| MEDIUM / LOW / INFO | 1,224 / 21 / 16 |

### Every CRITICAL, triaged by rule

| rule | count | verdict | what matched |
|---|---|---|---|
| `code_*` sandbox_escape (regex) | 3,394 | **FP** | `path.join(__dirname, "../../resources/icon.png")`, `realpathSync`, comments containing "symlink" — the same regex as A.1 |
| `code_*` code_execution (regex) | 1,754 | **FP** | the JS regex method `filePattern.exec(text)` matched `\bexec\s*\(`; also `child_process`/`spawn` in build scripts and tests |
| `poison_*_instruction_injection` | 60 | **FP** | single words: "never ", "always ", "you should" in ordinary descriptions (`get_shape_library`: "never …") |
| `toxic_combo_credential_access_network_external` / `code_execute_network_external` | 25 | **FP** | keyword classification: `get_drawing_guide` as "credential access", `open_panel`/`list_macros` as "code execution" |
| `instructions_instruction_injection`, `resource_*`/`prompt_*_instruction_injection` | 7 | **FP** | "never", "override" inside server instructions / a scraping guide resource |
| `poison_*_exfil_instruction` / `*_exfil_instruction` | 6 | **FP** | the word "webhook" in `monitor_create` (a webhook parameter) and "Include context" in a parameters reference |
| `cap_run_macro_shell_exec` and two more `cap_*_shell_exec` | 3 | **TP (capability)** | `A9T9/RPA` `run_macro`: "Run a macro again … pass script"; a UI-automation server that runs stored macros does execute — correct as a HIGH/CRITICAL *capability* note, not evidence of hostility |
| `mcp01_secret_*` provider-shaped | 5 | **FP (3) / needs a human (2)** | `Cotal` `stored-sessions.smoke.ts:178` a `sk-live-…` string in a **test** of a redaction function (FP); `empryo` `redact.ts:49` a PEM regex *inside a redactor* (FP); `cloud-audit` `generate_report_screenshot.py:83` an `AKIA…` id used as sample data in a report screenshot script (needs a human: looks like an example, value not verified); two `sk-`-shaped literals elsewhere, values not inspected (needs a human) |
| `ast_*` command_injection `shell=True` | 2 | **needs a human** | `sugar/executor/hooks.py:64` `subprocess.run(cmd, shell=True)` in a hooks executor — real sink, no evidence of caller input |
| `ast_0003` path traversal literal | 1 | **FP** | the docstring "without letting one escape the directory" in `storage.py:118` |
| `instructions_injection_marker` | 1 | **FP** | "the Finnish school **system: the** mark" matched the case-insensitive `SYSTEM:` marker |

**Critical false-positive rate on the registry sample (before): 5,253 / 5,258 ≈ 99.9 %.** Three CRITICALs are correct capability notes (`run_macro` and siblings), two need a human. No confirmed hostile server in the sample — which is what a sample of a public registry should look like, and what makes it a false-positive corpus.

### True positives worth a note

- `A9T9/RPA` — a UI-automation server whose `run_macro` executes stored scripts; combined with file access this is a real HIGH blast radius, by design. Documented honestly by its own descriptions.
- `roboticforce/sugar` — `subprocess.run(cmd, shell=True)` in a hooks executor: a code-quality finding for the maintainers, not agent-hostile.

## After (Part C)

The same corpora were re-scanned on 2026-11-05 with the scanner frozen at `555cd41` (scanner code identical to `ee9f93b`, the last rule change). Raw: `proofs/*/raw_after/`.

| corpus | | before (`5f3d93b`) | after (`555cd41`) |
|---|---|---|---|
| Reference servers (7) | rated *critical* | 7 | 0 |
| | CRITICAL / HIGH | 81 / 236 | 0 / 0 |
| | MEDIUM / LOW / INFO | 25 / 11 / 2 | 28 / 19 / 7 |
| Registry sample (45 scanned) | rated *critical* | 36 | 5 |
| | CRITICAL / HIGH | 5,258 / 2,943 | 30 / 82 |
| | MEDIUM / LOW / INFO | 1,224 / 21 / 16 | 849 / 5,569 / 1,122 |
| Live localhost (A.3) | risk; findings | medium / 30; 2 HIGH | safe / 0; 2 INFO |

Per reference server, after (critical / high / medium / low / info): `everything` 0/0/3/5/0 · `fetch` 0/0/0/0/3 · `filesystem` 0/0/11/12/1 · `git` 0/0/9/1/0 · `memory` 0/0/2/1/2 · `sequentialthinking` 0/0/3/0/0 · `time` 0/0/0/0/1.

**Critical false positives after: 29 of 30 CRITICALs on the registry sample, 0 on the reference servers.** The triage of all 30, the HIGH breakdown and what was deliberately left unfixed are in `LAUNCH_READINESS.md` (Part A.2). The largest group, 21 `oauth_metachar` findings on `Cotal-AI/Cotal` smoke tests, is a false-positive class introduced by a Part C fix.

## Phase 5 — second round of fixes, and a fresh sample (scanner frozen at `fe6d5dc`, 2026-11-11)

The corpora in this file are **tuned** from here on: Phase 4 Part C was written against the reference servers and registry sample 1, and Phase 5 Part 1 was written against the 29 critical false positives listed above. Their "before" columns remain the only independent numbers they will ever have. The independent false-positive number is now registry sample 2.

| corpus | | before (`5f3d93b`) | Phase 4 after (`555cd41`) | Phase 5 after (`fe6d5dc`) |
|---|---|---|---|---|
| Reference servers (7) | rated *critical* | 7 | 0 | 0 |
| | CRITICAL / HIGH | 81 / 236 | 0 / 0 | 0 / 0 |
| | MEDIUM / LOW / INFO | 25 / 11 / 2 | 28 / 19 / 7 | 44 / 20 / 11 |
| Registry sample 1 | repositories scanned | 45 | 45 | 50 |
| | rated *critical* | 36 | 5 | 2 |
| | CRITICAL / HIGH | 5,258 / 2,943 | 30 / 82 | 2 / 20 |
| | MEDIUM / LOW / INFO | 1,224 / 21 / 16 | 849 / 5,569 / 1,122 | 1,033 / 6,851 / 1,592 |
| **Registry sample 2 (held out)** | repositories scanned | | | **49 of 50** |
| | rated *critical* | | | **1** |
| | CRITICAL / HIGH | | | **1 / 20** |
| | MEDIUM / LOW / INFO | | | 467 / 6,001 / 1,520 |
| Live localhost (A.3) | risk; findings | medium / 30; 2 HIGH | safe / 0; 2 INFO | safe / 0; 2 INFO |

The Phase 5 column for the reference servers and sample 1 comes from fresh clones taken on 2026-11-11 (the Phase 4 clones were gone), so it is a newer snapshot of the same projects; commits are recorded in `proofs/registry-sample/rescan_log.json`. All 50 sample-1 repositories could be checked out this time.

**Registry sample 2.** Same selection method, seed `20261105`, the 50 repositories of sample 1 excluded, drawn from the registry as of 2026-11-11 (62,251 latest entries, 30,986 with a unique GitHub repository). Scanned once with the rules frozen. **Critical false positives: 1 of 1 CRITICAL. HIGH: 19 false positives of 20.** One repository crashed the scanner and is not counted. The triage of all 21 findings, line by line, and the list of rule families left unfixed are in `LAUNCH_READINESS.md` (Phase 5, Part 2). Raw: `proofs/registry-sample-2/raw/`; list and counts: `proofs/registry-sample-2/scan_log.json`.
