# LAUNCH_READINESS.md — Axiom 0.6.0, how it was measured

What the scanner was measured against before release, what it scored, and what the numbers do and do not show. Phase 5 (2026-11-11) is reported first; the Phase 4 record it builds on follows.

Commit hashes in this document (`fe6d5dc`, `555cd41`, `5f3d93b`, …) identify the scanner version each measurement was taken with. They belong to the pre-release development history, which is not part of this repository; the raw outputs of every measurement are under `proofs/`.

| | |
|---|---|
| Rules frozen for the Phase 5 measurement | `fe6d5dc`. Every Phase 5 number below was taken with the scanner at this version |
| After the measurement | one crash fix found by the measurement (not a rule), then licence, documentation and release files. Before release (2026-11-23): the built-in MCP CVE list was rewritten with published identifiers and matched on exact versions; replayed on the manifests and lockfiles of every measured repository at the measured commits, it adds no finding. Scanning by package name and the usage ping were fixed (see `CHANGELOG.md`); neither is a rule |
| Test suite | 743 passed (`pytest tests/`), up from 555 |
| In-house test bed proofs | 6/6 at `fe6d5dc`, and 6/6 again on the released code |
| Licence | Apache-2.0 |
| Date of the measurement | 2026-11-11 |

## Phase 5 — exit test

| condition | result |
|---|---|
| at most 9 critical false positives on a registry sample the rules have never seen | **passed: 1** |
| 0 CRITICAL and 0 HIGH on the official reference servers | **passed: 0 / 0** |

The fresh sample was drawn, cloned and scanned once, after the rules were frozen. No rule has been edited since, including for the false positives listed below.

## Phase 5, Part 1 — the four rule fixes

Each is one commit with regression tests (`tests/test_phase5_fp.py`); `docs/SEVERITY.md` records the new behaviour. The hashes are development-history commits.

| commit | fix |
|---|---|
| `f1e1c96` | One definition of a non-production path, `is_non_production_path()`, shared by the secret and OAuth rules. Adds `smoke/`, `scripts/`, `bench/`, `demo/`, `.github/` and `*.smoke.*`; whole path segments only. |
| `285b54c` | `oauth_metachar`: shell syntax must sit inside the quoted http(s) URL value. A statement's own `;`, an `&&` later on the line, or an `issuer` whose value is not a URL no longer match. **The `mcpsecbench` path carve-out is removed**; no file under `app/` contains that string. |
| `a91afef` | Secret-shaped literals: vendor samples marked `EXAMPLE`, masked values, PEM headers with no key material, arguments of redaction calls, a redactor's `replacement:`, and the literal fallback of a CI `${{ secrets.X \|\| '…' }}` expression are no longer reported. |
| `2b7b530` | `cap_*_shell_exec`: a name token that also names other things (`spawn`, `exec`, `execute`, `system`, `eval`) is LOW unless the description or a parameter that can only carry a command confirms a shell. `toxic_combo_*`: never more than one level above the weaker contributing capability. |
| `fe6d5dc` | `docs/SEVERITY.md`. |

## Phase 5, Part 2 — measurement

### Fresh registry sample (held out)

Same method as Phase 4, new seed. The official MCP Registry listed **62,251** latest entries on 2026-11-11, **30,986** with a unique public GitHub repository. The 50 repositories of the first sample were excluded. A pool of 400 was drawn uniformly at random (seed `20261105`); 49 could not be resolved on GitHub; the 25 most-starred of the rest are the popular half and 25 more were drawn at random. All 50 were cloned at depth 1. The list, with stars, the commit scanned and per-repository counts, is `proofs/registry-sample-2/scan_log.json`; raw results are in `proofs/registry-sample-2/raw/`.

| | fresh sample, scanner at `fe6d5dc` |
|---|---|
| repositories selected / cloned / scanned | 50 / 50 / **49** |
| rated *critical* / high / medium / low / safe | 1 / 10 / 25 / 3 / 10 |
| CRITICAL findings | **1** (1 false positive, 0 correct) |
| HIGH findings | **20** (19 false positives, 1 correct) |
| MEDIUM / LOW / INFO | 467 / 6,001 / 1,520 |

**One scan failed.** `oozoofrog/mcp-baepsae` made the scanner exit with `UnicodeDecodeError`: `package.json` was read with the Windows code page instead of UTF-8. It is excluded from every count above. The crash was fixed afterwards; scanned afterwards, outside the measurement, that repository has 0 CRITICAL and 1 HIGH (a `postinstall` build hook). That result is kept apart in `proofs/registry-sample-2/post_fix/`.

**Every CRITICAL and HIGH, read at the line it points to:**

| repository | rule | severity | verdict | what matched |
|---|---|---|---|---|
| `man0l/slashloop` | `response_injection_*_secret_exposure` | CRITICAL | **FP** | "CTF-style flag": the computed object key `` [`next${horizonDays}Days`] `` in a returned object looks like `name{…}` to the flag pattern |
| `fliptheweb/yazio-mcp` | `mcp01_secret_*` | HIGH | **correct** | `DEFAULT_CLIENT_SECRET`, a real OAuth client secret hard-coded in `src/api/http.ts` (copied from another public project, per its own comment) |
| `MaxFreedomPollard/Compartment` | `mcp01_secret_*` (2) | HIGH | **FP** | `_HOLDER_TOKEN = "compartment-boot-secret-v1"` and `SESSION_TOKEN = "compartment-session-v3"`: domain-separation labels, documented as such on the lines above |
| `MaxFreedomPollard/Compartment` | `flow_memory_unlink_*_file_write` | HIGH | **FP** | `v.unlink(relation_id)` is a method of the vault object that removes a graph relation, not a file |
| `swap-api/swap-api` | `mcp01_secret_*` | HIGH | **FP** | `tokenOut: "0x…"`, an ERC-20 contract address in `mcp/test.ts` (the file name `test.ts` is not a non-production path under the shared definition) |
| `Noord-Ventures/vlak` | `egress_get_component_*` (2) | HIGH | **FP** | `https://vlak.dev/…`, the project's own component registry, which is what the tool exists to fetch |
| `Noord-Ventures/vlak` | `cap_terminal_shell_exec` | HIGH | **FP** | a UI component named `terminal` ("Renders streamed console output…"); no parameters |
| `czekaj/sf-transit-mcp` | `egress_get_service_info_*` (3) | HIGH | **FP** | three `transitous.org` links returned as the data source's coverage, usage-policy and privacy URLs |
| `MShekow/package-version-check-mcp` | `egress_*_desc_*` (2) | HIGH | **FP** | example download URLs (`dl.k8s.io`, the Azure CLI release host) quoted in a tool description |
| `MShekow/package-version-check-mcp` | `mcp05_tool_sink_*` | HIGH | **FP** | `subprocess.run(["mise", "registry", "--json"])`: fixed arguments, no tool input reaches it |
| `Goldentrii/AgentRecall-MCP` | `poison_*_sleeper_pattern` | HIGH | **FP** | the phrase "on first use" in a parameter description ("only on first use or major change") |
| `no-human-ai/no_human` | `provenance_mismatch` | HIGH | **FP** | the scanner compared the registry's repository with the package's `Homepage` URL instead of its `Source` URL, which matches |
| `mattheworiordan/remi` | `registry_typosquat_*` | HIGH | **FP** | `remit`, an unrelated project (a workflow language) one letter from `remi` (Apple Reminders) |
| `rjn32s/mcp-yolo` | `registry_typosquat_*` | HIGH | **FP** | `mcp-yoto` (the Yoto audio player) one letter from `mcp-yolo` (object detection) |
| `mattheworiordan/remi` | `manifest_postinstall` | HIGH | **FP** | `npm run build:swift \|\| echo …`: a build step. The hook exists, as reported; nothing about it is hostile |
| `man0l/slashloop` | `manifest_postinstall` | HIGH | **FP** | `prisma generate …`: a build step, same reading |

**What this means.** The CRITICAL label no longer fires on ordinary repositories: 1 finding in 49. That is the launch condition and it is met. It is not evidence that CRITICAL is precise: the one finding is wrong, and this sample contains no true critical to be right about. **HIGH is where the false positives now are**: 19 of 20. Seven are one rule (`egress_*`) treating a server's own API host or a documentation link as an exfiltration endpoint. None of this was fixed, on purpose: fixing and re-measuring on the same sample would turn it into a tuned corpus. The unfixed classes:

1. `egress_*`: the server's own API host, and URLs that are returned or quoted rather than sent to (7).
2. `mcp01_secret_*` generic literal: constants named `*_TOKEN` that are labels, and on-chain addresses (3 false, 1 correct).
3. `registry_typosquat_*`: an edit distance of one between unrelated projects (2).
4. `manifest_postinstall`: build steps at HIGH (2, plus 1 on the repository scanned after the crash fix).
5. One each: `provenance_mismatch` reading `Homepage` instead of `Source`; `cap_terminal_shell_exec` on a name alone; `flow_*_file_write` on a method called `unlink`; `sleeper_pattern` on "on first use"; `mcp05_tool_sink` on a fixed argument list; the CTF-flag pattern on a template-literal key (the one CRITICAL).

### The corpora the rules have seen (tuned)

The Phase 4 clones no longer existed, so every corpus was cloned again on 2026-11-11 and scanned at `fe6d5dc`. The repositories have moved since 2026-11-04 (the reference `filesystem` server has 16 tools, was 14), so the Phase 4 and Phase 5 "after" columns are different snapshots of the same projects, not the same files.

| corpus | Phase 4 after (`555cd41`) | Phase 5 after (`fe6d5dc`) |
|---|---|---|
| Reference servers (7), CRITICAL / HIGH | 0 / 0 | **0 / 0** (MEDIUM 44, LOW 20, INFO 11; 5 medium, 2 safe) |
| Registry sample 1, repositories scanned | 45 of 50 | **50 of 50** (`core.longpaths`; the 5 that could only be partly checked out are complete) |
| Registry sample 1, CRITICAL | 30 (29 false positives) | **2** (1 false positive, 1 correct capability note) |
| Registry sample 1, HIGH | 82 | **20** (not triaged one by one) |
| Registry sample 1, MEDIUM / LOW / INFO | 849 / 5,569 / 1,122 | 1,033 / 6,851 / 1,592 |
| MCPSecBench, server-side cases caught | 14 / 14 | **14 / 14** |
| Healthy localhost server | safe / 0, 2 INFO | safe / 0, 2 INFO |

- **All 29 Phase 4 critical false positives are gone** from sample 1 (21 `oauth_metachar`, 5 secret-shaped literals, 2 `spawn_`, 1 toxic combination). That is what the fixes were written to do; it is not an independent result.
- The 2 CRITICALs left on sample 1: `cap_run_macro_shell_exec` on `A9T9/RPA` (correct: the tool runs caller-supplied scripts by design), and `poison_check_open_design_artifact_priv_escalation` on `feimacode/open-design-agent-kit` (**FP**: "then skip the check and tell the user once that visual checking needs Chrome"). The second repository is one of the five that could not be checked out in Phase 4, so this finding is new to the corpus, not a regression.
- **MCPSecBench #14 is still caught without the carve-out.** `oauth_metachar_cve-2025-6514.py_45` fires on the file's own content, scanned alone and as part of the directory. The score stays 14/14 (5/14 held out).
- Clone commits: `modelcontextprotocol/servers` `e1dc4b1`, `AIS2Lab/MCPSecBench` `7612c5a`; per repository for sample 1 in `proofs/registry-sample/rescan_log.json`.

## Numbers that must not be rounded (Phase 5)

- **Critical false positives on the held-out sample: 1, not zero**, and that 1 is the only CRITICAL there. 0 of 1 CRITICALs are correct.
- **49 scanned, not 50.** One repository crashed the scanner and is excluded from the counts; its post-fix result (0 CRITICAL, 1 HIGH) is reported separately and is not part of the measurement.
- **HIGH on the held-out sample: 20, of which 19 are false positives.** This phase did not improve HIGH and did not try to.
- **Sample 1's "2 CRITICAL" is a tuned number**, and it is from a newer snapshot of 50 repositories, not the 45 scanned in Phase 4.
- **MCPSecBench: 5/14 held out, 14/14 after.** Unchanged, and still never to be quoted without the 5/14.
- **LOW and INFO are large** (6,001 and 1,520 on the fresh sample; one repository has 2,967 LOW). A default run is still noisy below MEDIUM.
- **DVMCP 15/15 is the Phase 3 number**, not re-run. Live scans of third-party servers were not run; MCPSecBench is scored static only.
- **Text files other than the two manifests are still decoded with the platform default** (`errors="ignore"`), so a scan of non-ASCII source on Windows can match slightly different text than on Linux. Not changed here because it touches what rules see.

## Known gaps

- The HIGH false positives listed above are not fixed in this release.
- The single-maintainer provenance signal is not built.
- DVMCP was not re-run after Phase 3, and no live scan of a third-party server has been run.
- macOS and Linux installs are exercised by CI, not by hand.

---

# Phase 4 record (2026-11-04 / 2026-11-05)

The Phase 4 report as written, with three later facts noted in place: the licence is now Apache-2.0, the benchmark-specific exception it describes has been removed, and the local paths it mentions have been rewritten. Its "after" numbers are the `555cd41` ones.

| | |
|---|---|
| Starting commit (held-out measurement) | `5f3d93b` — rename + E.1 (TypeScript parsing, Surface Map), **no rule changes before this point were made against Parts A/B** |
| Part C end commit (final "after") | `555cd41` — every "after" number in this record was taken with the scanner frozen at this commit; its scanner code is identical to `ee9f93b`, the last rule change |
| Test suite | 555 passed (`pytest tests/`), up from 435 at the start; re-run 2026-11-05 |
| In-house test bed proofs | 6/6 at every commit of the phase; re-run 2026-11-05 |
| Date | 2026-11-04; final rescan of all four corpora 2026-11-05 |

## Part A — false positives on servers we did not write

### A.1 Official reference servers (7)

| | before (`5f3d93b`) | after (`555cd41`) |
|---|---|---|
| servers rated *critical* | 7 / 7 | 0 / 7 (5 medium, 2 safe) |
| CRITICAL findings | 81 (all false positives) | 0 |
| HIGH findings | 236 (all false positives) | 0 |
| MEDIUM / LOW / INFO | 25 / 11 / 2 | 28 / 19 / 7 |

Per-server tables and the triage of every CRITICAL (quoted lines) are in `FP_BASELINE.md`. Where the 81 came from: 76 from a `realpath|symlink|path.join(..)` regex, 4 from single words ("silently", "always", "You should", "full scope") in descriptions, 1 from keyword "code execution" on `read_text_file`. The 236 HIGH: 203 OSV advisories matched without a version, 21 static "no auth" on the `everything` server's transport files, 7 toxic combos, 2 `os.environ.get`, 1 `sendToolListChanged`, 3 blast radius.

### A.2 Registry sample (50 selected, 45 scannable)

| | before (`5f3d93b`) | after (`555cd41`) |
|---|---|---|
| servers rated *critical* | 36 / 45 | 5 / 45 |
| CRITICAL findings | 5,258 (5,253 false positives; 3 correct capability notes; 2 need a human) | 30 (29 false positives; 1 correct capability note) |
| HIGH findings | 2,943 | 82 (59 of them on one repository) |
| MEDIUM / LOW / INFO | 1,224 / 21 / 16 | 849 / 5,569 / 1,122 |

**Critical false positives across the reference servers and the registry sample, before: 81 + 5,253 = 5,334 of 5,339 CRITICALs (99.9 %). After: 0 + 29 = 29 of 30 CRITICALs (96.7 %).** The count fell by a factor of 184; the *rate* barely moved, because almost nothing that is still CRITICAL in this corpus is a real problem. Both numbers are true and neither should be quoted without the other. Selection method, the five repositories that could not be checked out on Windows, and the per-rule triage are in `FP_BASELINE.md`; the sample list is `proofs/registry-sample/scan_log.json`.

**The 30 CRITICALs that survive, every one read at the line it points to:**

| repository | count | rule | verdict | what matched |
|---|---|---|---|---|
| `Cotal-AI/Cotal` | 21 | `oauth_metachar_*` | **FP** | ordinary `issuer` assignments in smoke tests (`const issuer = "http://127.0.0.1:9";`, `createUserTokenIssuer({ issuer: "https://auth.cotal.test", key: await generateSigningKey() })`). The rule was added in Part C for MCPSecBench #14. Its pattern (`_OAUTH_URL_RE` in `app/analysis/tool_body_detectors.py`) accepts `issuer = "` followed within 200 characters by `;`, whitespace and a word, so the statement's own terminating semicolon plus the next statement's first keyword counts as a shell metacharacter; `&&` and `\|\|` later on the line match the same way. It skips paths containing `test` but not `smoke`. **This false-positive class was created by a Part C fix.** |
| `Cotal-AI/Cotal` | 1 | `mcp01_secret_*` | **FP** | a key-shaped string passed to a redaction function inside its own smoke test |
| `A9T9/RPA` | 1 | `cap_run_macro_shell_exec` | **correct capability note** | `run_macro` runs stored scripts, by design |
| `A9T9/RPA` | 1 | `toxic_combo_code_execute_filesystem` | **FP** | derived from `run_macro` plus `delete_macro` classified as "filesystem" by keyword |
| `roboticforce/sugar` | 2 | `cap_spawn_*_shell_exec` | **FP** | the evidence is the tool-name prefix `spawn_`; nothing shows a shell |
| `roboticforce/sugar` | 1 | `mcp01_secret_*` | **FP** | a dummy fallback key in a CI workflow (`secrets.ANTHROPIC_API_KEY \|\| '<test placeholder>'`) |
| `gebalamariusz/cloud-audit` | 2 | `mcp01_secret_*` | **FP** | AWS's documented `…EXAMPLE` access key id, used as sample data in a screenshot script |
| `proxysoul/empryo` | 1 | `mcp01_secret_*` | **FP** | the replacement placeholder string inside a secret redactor |

**HIGH (82):** 59 are on `Cotal-AI/Cotal` — "generic secret literal" (55) and "bearer token" (4), 58 of them in smoke-test files and one a dev-only identity provider fixture; not triaged one by one. The other 23 are spread over 9 repositories (shell-exec capability 8, blast radius 4, supply chain 4, secrets 3, toxic combo 2, prompt injection 1, tool poisoning 1) and were **not individually triaged**.

**What this means for launch.** Two rule families produce 26 of the 29: `oauth_metachar` on test code (21) and secret-shaped literals in tests, examples and redactors (5). Neither was fixed in this phase, deliberately: fixing and re-measuring again would be a third pass over the same 50 repositories, which is tuning against the test. Both were fixed in Phase 5 and measured on a **fresh** registry sample; see the top of this document.

### A.3 Live, healthy localhost server, no auth

`tests/fixtures/healthy_http_server.py` on `127.0.0.1:3010` (a third-party server could not be run in the test environment; see "Not measured").

| | before | after |
|---|---|---|
| risk | medium / 30 | safe / 0 |
| findings | `plain_http` HIGH, `no_auth` HIGH | `plain_http` INFO, `no_auth` INFO |

## Part B — MCPSecBench (held out)

| | before (`5f3d93b`, held out) | after (`555cd41`, tuned) |
|---|---|---|
| server-side cases in scope | 14 | 14 |
| caught | 5 | 14 |
| partial | 2 | 0 |
| missed | 7 | 0 |
| out of scope (client / browser / network) | 3 | 3 |

**Only the before column is independent.** Part C fixed the seven misses and two partials while looking at MCPSecBench, so 14/14 shows the fixes work on the cases they were written for. One of those fixes (`oauth_metachar`, case #14) is the source of 21 of the 29 critical false positives in A.2.

Case-by-case tables, the exact artefacts and the gap list are in `HELDOUT_RESULTS.md`; the after table is regenerated into `docs/COVERAGE.md`. (The ledger's strict id-count reads the before as 6/14 because it counts #13's `bind_all` as a catch; the manual verdict was *partial*.)

## docs/SEVERITY.md — summary

Capability is not intent: file/process/env/network access is INFO/LOW unless it combines with poisoning, injection, exfiltration, a secret or a rug-pull primitive on the same server, or a caller parameter flows into the sink unchecked. Transport severity depends on the host (loopback INFO, private range LOW, public HIGH). Whole-file regex and AST sink hits are capability notes. Advisories are matched to the locked version and rated by the advisory, capped at HIGH. Derived findings (toxic combo, blast radius) never outrank their inputs. The risk level is set by the worst finding, so notes never add up to "medium". Every rule's severity and rationale are tabled in the document; `app/analysis/severity_policy.py` implements the host classes and the score.

## Part E — the agent-surface model

- **E.1 TS fixture score: 12/12.** `tests/fixtures/evil_server.ts` (a port of the test bed's `evil_server.py`) produces the same 35 non-INFO findings with the same ids and severities as the Python original (only the `ast_`/`code_` id prefixes differ), and the **same Surface Map fingerprint**: `f8982da3919fb477539299d885fcaf9edc94b3931a87c227c783a289a7e62d21`. A live scan of the running Python server produces that same fingerprint (`live --source` reports 0 mismatches); a one-word description change produces exactly one `surface_mismatch_tool_changed_*`. Sample map (TS fixture, `run_command`):

  ```json
  {"name": "run_command", "description": "Run a shell command on the host and return its output.",
   "input_schema": {"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]},
   "capabilities": ["exec"], "return_literals": ["text", "[testbed] would execute via shell: {cmd}"],
   "registration": "static", "location": "evil_server.ts:71"}
  ```
  Registration patterns verified against the official TypeScript SDK and all four TS reference servers (`registerTool`, `tool`, `registerResource`, `registerPrompt`, `setRequestHandler`, `new McpServer({...}, {instructions})`); 63 tools extracted from the 7 reference servers with names, descriptions and schemas matching source.
- **E.2 SARIF:** `--output sarif` validates against the OASIS SARIF 2.1.0 schema (`tests/test_phase4_replay.py::TestExports::test_sarif_validates_against_schema`, schema file committed under `tests/fixtures/`). One rule per Axiom rule id with `owasp_asi` / `owasp_mcp` in `properties`, `physicalLocation` + `region.startLine` where known, evidence and replay per result, `--fail-on`. GitHub Code Scanning upload is in the README.
- **E.2 AIBOM:** `--output aibom` emits CycloneDX 1.5; for the TS fixture: 10 tool components, 1 resource, 1 prompt, the server as `metadata.component` with the fingerprint as a SHA-256 hash, 29 vulnerabilities each `affects` the tool it was found on. Sample excerpt: the `run_command` component carries `axiom:capabilities ["exec"]`, `axiom:parameters ["cmd"]`, `axiom:location evil_server.ts:71`.
- **E.3 Provenance:** `app/analysis/provenance.py`. Real output for `domdomegg/airtable-mcp-server` (from the registry sample): `registry.status = "match"`, entry `io.github.domdomegg/airtable-mcp-server`, repository `https://github.com/domdomegg/airtable-mcp-server`, packages `npm:airtable-mcp-server`, published 2026-07-27, no lookalikes. Mismatch, typosquat and fresh-publish paths are unit-tested with a mocked registry. OSV is version-aware with lockfile support and a 24 h cache; `--no-deps` skips all network lookups.
- **E.4 Replay invariant:** every finding carries `rule_id`, `evidence`, `location`, `replay`; `tests/test_phase4_replay.py::TestInvariant` enforces it on static (both fixtures), live (fake stdio server) and config scans. `axiom explain <id> --from scan.json` prints all four. Coverage ledger: `docs/COVERAGE.md`, regenerated by `tools/coverage_ledger.py` and checked in CI.

## The README headline sentence, as it shipped in Phase 4 (replaced in Phase 5)

> **In-house bed 12/12 + 8/8 · DVMCP 15/15 · MCPSecBench 14/14 (server-side cases) · 29 critical false positives across the official reference servers and 50 registry servers.**

This is the spec's exact form with the "after" numbers. The README prints it with the qualifiers it needs directly underneath: MCPSecBench was 5/14 held out and is 14/14 only after fixes written against it; the 29 are all in the registry sample (0 on the reference servers), down from 5,334; 45 of the 50 registry repositories could be scanned.

Tuned on: in-house bed, DVMCP. Held out at the starting commit: MCPSecBench, reference servers, registry sample.

## Not measured, and why

- **Live scans of third-party servers** (a reference server over HTTP, MCPSecBench live, a DVMCP re-run): downloaded server code was not executed in the test environment. The live false-positive check used a 50-line healthy server written for the purpose; MCPSecBench is scored static only; DVMCP's 15/15 is the Phase 3 number and is marked *tuned, not re-run* in the ledger.
- **Five registry repositories** could not be checked out on NTFS in Phase 4 (invalid filenames / long paths); they are listed in `FP_BASELINE.md` and excluded from the Phase 4 counts. All 50 were checked out in Phase 5.
- **`uvx` / `pipx` on macOS and Linux** were not run by hand; the Linux clean-wheel smoke runs in CI.
- **Single-maintainer + install-script provenance signal** (E.3) was not built: it needs authenticated GitHub API calls; `provenance_fresh_publish` and install-hook findings cover the rest.

## Numbers that must not be rounded (Phase 4)

- **MCPSecBench: 5/14 held out, 14/14 after.** Never quote 14/14 without 5/14. Counting the two partials as half, the held-out score is 6/14.
- **Critical false positives: 29, not zero.** 0 on the 7 reference servers; 29 on the registry sample, in 5 of 45 scanned repositories; 21 of them from one rule on one repository.
- **96.7 % of surviving CRITICALs are false positives** (29 of 30). The count is small; the precision of the CRITICAL label on real-world repositories is still poor.
- **45 scanned, not 50.** Five registry repositories could not be checked out on Windows and are excluded from every count.
- **HIGH findings after: 82 on the registry sample, not triaged individually.** 59 are secret-shaped literals in one repository's test files.
- **LOW and INFO rose** (LOW 21 → 5,569, INFO 16 → 1,122 on the registry sample): Part C demoted whole-file pattern hits to capability notes instead of removing them. A default run on a large repository is still noisy below MEDIUM.
- **DVMCP 15/15 is the Phase 3 number**, not re-run in Phase 4.
- **Live scans of third-party servers were not run**; MCPSecBench is scored static only.
- The raw result files under `proofs/` recorded the absolute local path of each scanned clone. (Rewritten to a neutral root in Phase 5.)
- **The scanner contains a benchmark-specific exception.** `detect_oauth_metacharacters` skips files whose path contains `test` *unless the path also contains `mcpsecbench`*. That carve-out exists so case #14 is still caught when the benchmark sits in a directory with "test" in its name; it is a rule keyed on the benchmark's name and should be removed (found while writing this report, not changed in this phase). (Removed in Phase 5, commit `285b54c`; case #14 is still caught.)
