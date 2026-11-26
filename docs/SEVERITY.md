# Severity policy

Axiom reports what is **hostile to an agent**, not what is merely powerful or merely
buggy. Severity answers one question: *if an agent trusted this server, how badly and how
directly could it be turned against its user?* The policy below is what every rule is
calibrated to. It was written in Phase 4 after measuring the scanner, unchanged, on the
seven official reference servers, a 50-server registry sample and MCPSecBench
(`FP_BASELINE.md`, `HELDOUT_RESULTS.md`); the rules in this repository implement it.

## Levels

| Level | Meaning | Exit code |
|---|---|---|
| **CRITICAL** | The artefact *is* an attack: hidden instructions, exfiltration to a baked-in endpoint, a live secret, a shell reachable from a tool argument, a surface that changed after approval. Do not install. | 2 |
| **HIGH** | A direct path to harm that needs one more thing (a hijacked prompt, an unauthenticated network, a confused agent). Review before installing. | 2 |
| **MEDIUM** | Steering language, over-broad scope, weak hygiene that widens an attack. Worth a look. | 1 |
| **LOW** | A capability or configuration note that only matters in combination with something else. | 0 |
| **INFO** | Inventory: what the server can do. Never a finding on its own. | 0 |

## Principles

1. **Capability is not intent.** A tool that reads files, runs a process, reads an
   environment variable or makes an HTTP request is doing what MCP servers are for. On its
   own that is **INFO/LOW** (a capability note, visible in the Surface Map). It becomes a
   finding only when it **combines with intent** on the *same tool or server*: a poisoned
   description, an injection marker, an exfil destination, a secret, a rug-pull primitive,
   or a caller-controlled argument flowing straight into the sink. This is the rule the
   toxic-combo logic already modelled; per-tool severities now follow it.
2. **Location changes severity.** Transport findings depend on where the server is:
   public host → **HIGH**; private range (10/8, 172.16/12, 192.168/16, fc00::/7) → **LOW**;
   `127.0.0.1` / `localhost` / `::1` → **INFO**. A localhost server without TLS or auth is how
   every stdio-wrapped and dev server works.
3. **Evidence must be quotable.** A rule fires on text or code it can quote. A keyword in a
   comment, an import, or a long tutorial-style description is not evidence of hostility.
   Regex over whole source files is restricted to patterns that are hostile *by
   themselves* (invisible Unicode, hard-coded sink URLs, credentials). Generic
   sink/API regexes (`realpath`, `symlink`, `..`, `fs.readFileSync`, `os.environ.get`,
   `fetch(`) are **capability notes** (INFO), never findings.
4. **Advisories are a signal, not the headline.** A dependency advisory is reported only
   when the version is inside the affected range, and never at CRITICAL for a transitive
   package. A dependency whose version is unknown gets one **INFO** note, not every
   advisory ever published. OSV advisories are reported at **MEDIUM** (direct) or **LOW**
   (transitive): the batch lookup does not return the advisory's own rating, so it is not
   used. The one exception to "not the headline" is the short built-in list of MCP CVEs,
   which is matched on the exact version only and keeps the advisory's own severity.
5. **Derived findings never outrank their inputs.** Blast-radius and toxic-combo findings
   are computed from other findings and capabilities; their severity is at most the highest
   contributing severity, and they are INFO when nothing else fired. A combination is also
   never more than one level above its *weaker* input.
6. **Held-out numbers are kept.** Severity changes are measured before and after on the
   same corpora; `docs/COVERAGE.md` records both.

## Non-production paths

One definition, `is_non_production_path()` in `app/analysis/mcp_top10_detectors.py`, shared
by every path-sensitive rule. A path is non-production when one of its **whole segments** is
`test(s)`, `__tests__`, `spec(s)`, `fixture(s)`, `example(s)`, `sample(s)`, `mock(s)`, `e2e`,
`doc(s)`, `smoke`, `scripts`, `bench`, `benchmark(s)`, `demo(s)` or `.github`, or when the
file name is `*.test.*`, `*.spec.*`, `*.smoke.*`, `test_*` or `*_test.py`. Substrings do not
count (`latest/`, `contest.py` are production paths), and no benchmark or project is named.

| Rule | In a non-production path |
|---|---|
| `mcp01_secret_*` | LOW (the value may still be live; it is not what the server ships) |
| `oauth_metachar_*` | not reported |

## Transport

| Rule | Host | Severity | Rationale |
|---|---|---|---|
| `live_<server>_no_auth`, `transport_no_auth`, `config_<s>_no_auth` | public | HIGH | anyone on the internet can drive the agent's tools |
| same | private range | LOW | reachable only on the LAN; worth knowing, not an attack |
| same | localhost | INFO | the normal state of a dev/stdio-wrapped server |
| `live_<server>_plain_http`, `transport_plain_http` | public | HIGH | credentials and tool results in the clear |
| same | private / localhost | LOW / INFO | no path for an off-host attacker |
| `mcp07_bind_all` (binds 0.0.0.0) | — | MEDIUM | exposes a server its config describes as local |
| `transport_session_url` (session id in URL) | — | MEDIUM (was HIGH) | the legacy SSE design; a leak vector, not an attack |

## Capabilities (per tool)

`cap_<tool>_<capability>` — `shell_exec`, `file_read`, `file_write`, `env_dump`, `network_egress`.

| Situation | Severity | Rationale |
|---|---|---|
| Capability present, no intent signal on the tool or server | INFO (`env_dump`, `network_egress`, `file_read`, `file_write`), LOW (`shell_exec`) | inventory; a filesystem server reads files |
| `shell_exec` suggested only by a name token that also names other things (`exec`, `execute`, `system`, `eval`, `spawn`), with no description evidence and no parameter that can only carry a command (`cmd`, `command`, `script`, `shell`) | LOW | `spawn_subagent(args)` and `execute_query(code)` are not shells; a wrapper `args` object or a `code` payload confirms nothing |
| The description itself says the tool is unrestricted ("any file on disk", "arbitrary command", "all environment variables") | HIGH (`file_*`, `env_dump`), CRITICAL (`shell_exec` with a command-like parameter) | the server advertises an unrestricted primitive to the model |
| A caller-supplied parameter flows into `open()` / `subprocess` / `fetch()` with no visible check | HIGH (`file_read`/`file_write`/`network_egress`), CRITICAL (`shell_exec`) | the argument is the attack surface; see `mcp05_tool_sink` |
| Capability + poisoning / injection / exfil / secret / rug-pull on the same server | raise one level, max CRITICAL | capability combined with intent |

Raw code-pattern hits (`code_*`, `ast_*`) for env reads, outbound HTTP, file APIs, `realpath`/`symlink`/`..`: **INFO** capability notes. `eval`/`exec`/`os.system`/`child_process` in source: **LOW**, and HIGH/CRITICAL only through `mcp05_tool_sink_*` (inside a tool handler) or `command_injection` (shell string built from input). `/etc/passwd`, `/proc/self`, `chroot`: LOW.

## Toxic combinations and blast radius

`toxic_combo_<a>_<b>` fires only when **both** capabilities come from strict per-tool rules (the `cap_*` table), not from loose keyword classification; severity = the higher of the two contributing `cap_*` findings, max HIGH, CRITICAL only when one side is a CRITICAL `shell_exec`, and in every case at most one level above the **weaker** contributing finding (a CRITICAL shell tool next to a scoped LOW delete is MEDIUM). `blast_radius_estimate` is INFO unless at least one MEDIUM+ non-derived finding exists, and never above the highest of them.

## Descriptions, instructions, resources, prompts (text rules)

| Rule | Severity | Rationale |
|---|---|---|
| `*_injection_marker` (`<IMPORTANT>`, "ignore previous instructions", "do not tell the user", "system note") | CRITICAL | the canonical poisoning payload |
| `*_invisible_unicode` | CRITICAL | text the reviewer cannot see |
| `*_secret_exposure` (a credential in served text) | CRITICAL | the model receives a live secret |
| `poison_<tool>_tool_shadowing` (names another tool/server and changes its behaviour) | CRITICAL | cross-server hijack |
| `poison_<tool>_exfil_instruction`, `*_egress_<n>` to a sink-looking host | CRITICAL / HIGH | data leaves to an attacker's endpoint |
| `poison_<tool>_preference_override` ("use this tool rather than others", "no matter how many arguments", "replace the values") | HIGH | steering the agent away from the correct tool |
| `poison_<tool>_instruction_injection` — imperative phrase ("always", "you should", "silently", "before responding") | **MEDIUM** steering language; HIGH when the phrase targets a sensitive path, another tool, or the user's knowledge ("do not mention") | reference servers use these words in ordinary guidance ("will succeed silently", "You should: 1. Start with…") |
| `poison_<tool>_priv_escalation` ("bypass auth", "admin access", "unrestricted access") | HIGH; CRITICAL for "bypass/skip/disable auth|security|consent" | "full scope" alone is English, not escalation |
| `poison_<tool>_tool_chaining` | MEDIUM | often legitimate workflow guidance |
| `poison_<tool>_sleeper_pattern` | HIGH | behaviour that changes after N uses |
| `*_invokes_dangerous_tool` (served text steers to a tool with a HIGH+ capability) | HIGH | content-driven tool misuse |
| `*_sensitive_path` (`~/.ssh`, `.aws/credentials`, `mcp.json` in served text) | HIGH | the text points the model at secrets |
| `*_restricted_name` (`internal://`, `secret`, `admin` resource names) | MEDIUM; HIGH when served without auth | an invitation, not yet a payload |
| `poison_<tool>_homoglyph`, `shadow_<tool>_near_duplicate` | HIGH / MEDIUM | lookalike names; HIGH when the twin is dangerous |
| `poison_<tool>_long_desc`, `poison_<tool>_mismatch` | LOW / MEDIUM | hygiene; a long description is suspicious only with other signals |
| `scope_<tool>_<param>_excessive` (`*`, `.all`, root paths as defaults) | HIGH | default-on over-scoping |
| `identity_override_<tool>_<param>` / `authz_input_<tool>_<param>` | HIGH / MEDIUM | the caller chooses whose identity/authorisation applies |
| `schema_<tool>_context_param` (parameter asks for the tool list, conversation, system prompt, other keys) | HIGH | schema-level exfiltration of context |
| `schema_<tool>_doc_mismatch` (documented arguments ≠ schema) | LOW | inconsistency; MEDIUM when an undocumented parameter exists |

## Mutation (rug pull)

| Rule | Severity | Rationale |
|---|---|---|
| `rugpull_remove_tool_*`, a tool registered from inside another tool's callback | HIGH | the surface changes after approval, by the server's own choice |
| `rugpull_counter_<tool>` (behaviour gated on an invocation counter) | HIGH | benign for N calls, different afterwards |
| `rugpull_docstring_<tool>` (a tool rewrites its own `__doc__`/description) | HIGH; CRITICAL if the new text carries an injection marker | the rewritten text is the payload |
| `rugpull_add_tool_*` at import/startup, `sendToolListChanged`, `listChanged: true` | MEDIUM (`listChanged`, `sendToolListChanged`), INFO (startup registration) | advertising mutability is a capability, not an attack |
| `surface_mismatch_tool_added_*`, `*_tool_changed_*` (description) , `surface_mismatch_instructions` | HIGH | the running server is not the reviewed code |
| `surface_mismatch_tool_changed_*` (schema only), `*_resource_added_*`, `*_prompt_added_*` | MEDIUM | |
| `surface_mismatch_tool_missing_*` | INFO | |
| `diff_<server>_<tool>_runtime_only` (live tool absent from `--compare` source) | HIGH (was CRITICAL) | same as `surface_mismatch_tool_added` |

## Supply chain and provenance

| Rule | Severity | Rationale |
|---|---|---|
| `dep_known_<pkg>` (curated known-malicious MCP package list; empty in this release) | CRITICAL | a known-bad artefact |
| `CVE-*` from the built-in MCP CVE list (rule `known_mcp_cve`), exact version in the affected range. The exact version is the lockfile's, or the manifest's when it is pinned exactly | the advisory's own severity (CRITICAL or HIGH) for a direct dependency; one level lower (HIGH or MEDIUM) for a transitive one | a published vulnerability in an MCP package the project depends on |
| `CVE-*_unversioned` from the built-in list (rule `known_mcp_cve_unpinned`): no exact version, for example a range such as `^0.1.10` with no lockfile | INFO (one note per package) | cannot be confirmed |
| the OSV finding for an advisory the built-in list has already reported | not reported | the same advisory, counted once |
| `GHSA-*`/`CVE-*` dependency advisory from OSV, version in affected range | MEDIUM; LOW if transitive | real but usually not agent-hostile; the advisory's own rating is not available from the batch lookup |
| advisory, version unknown | INFO (one note per package) | cannot be confirmed |
| `manifest_<hook>` (install lifecycle scripts) | MEDIUM; HIGH when the script downloads or executes remote content | scripts run at install, but most are builds |
| `manifest_bin_*`, `manifest_py_cmdclass` | MEDIUM | |
| `mcp04_unpinned_*`, `config_<s>_npx_unknown`, `unpinned_runtime_install_<tool>` | MEDIUM | `latest` is a rug pull waiting to happen |
| `provenance_mismatch` (registry entry points elsewhere), `registry_typosquat` | HIGH | not the package it claims to be |
| `supply_chain` (fresh publish, single maintainer + install scripts, `latest`) | MEDIUM | |

## Secrets and configs

| Rule | Severity | Rationale |
|---|---|---|
| `mcp01_secret_*` with a provider-shaped key (`sk-…`, `AKIA…`, `ghp_…`) or a connection-string password | CRITICAL | a live credential in the artefact |
| `mcp01_secret_*` generic high-entropy assignment | HIGH | |
| `mcp01_secret_*` in a non-production path (see above) | LOW | test, example, tooling and CI material |
| key-shaped value that is a vendor sample marked `EXAMPLE`, a masked value (`…***`), or a PEM private-key header with no key material after it | not reported | a placeholder, a marker or a parser constant, not a credential |
| key-shaped value that is the argument of a redaction/masking call, a redactor's `replacement:`, or the literal fallback of a CI `${{ secrets.X \|\| '…' }}` expression | not reported | the code exists to remove or stand in for the secret |
| `oauth_metachar_*` (shell syntax **inside the quoted http(s) URL value** of an OAuth metadata key, or inside a bare URL token on an OAuth metadata line) | CRITICAL | the CVE-2025-6514 pattern. Text after the closing quote is code, not the URL; a key such as `issuer` whose value is not a URL does not match |
| `config_<s>_hardcoded_secret` | CRITICAL | a credential in a client config |
| `config_<s>_env_<key>` (secret-named env var passed to a server) | LOW (was HIGH) | that is how servers are configured; the *value* is not exposed |
| `config_<s>_env_overexposed`, `cross_env_<key>` | MEDIUM | one secret shared with many servers |
| `config_<s>_dangerous_cmd` | HIGH | a shell as the server command |
| `discover_unapproved_*` | HIGH | shadow servers outside the allowlist |

## Code-quality detectors kept at advisory level

`codegen_*`, `memory_*`, `interagent_*`, `trust_*`, `rogue_*`, `mcp08_no_tool_logging`, `mcp10_broad_exposure_*`, `semgrep_*`: **LOW/INFO** unless the matched text is inside a tool/resource/prompt definition or a served string, in which case the text rules above apply and this detector's own finding is dropped as a duplicate.

## What is never a finding

- A server running on localhost without TLS or auth.
- A tool that reads files, writes files, runs processes or fetches URLs, described honestly and scoped by its own description, with no other signal.
- A client reading its own API key from its environment.
- `realpath`, `symlink`, `..`, `path.join(…, "..")`, `/etc/passwd` in source.
- Advisories for versions the project does not use.
- Words such as "always", "never", "silently", "you should", "full scope" in otherwise ordinary guidance.
