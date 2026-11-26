# Axiom file formats

This page describes the two data files you are most likely to write or edit yourself:

- [Approved server allowlist](#approved-server-allowlist) used by `axiom discover --allowlist` and `axiom threatmodel --from-discover --allowlist`
- [Threat rule catalogue](#threat-rule-catalogue) (`data/threat_catalogue.json`) used by `axiom threatmodel`

Both are plain JSON.

---

## Approved server allowlist

A JSON document listing the MCP servers your organisation has reviewed. A complete example ships as [`data/approved_servers.example.json`](../data/approved_servers.example.json).

```json
{
  "version": 1,
  "servers": [
    {
      "name": "github",
      "install_source": "npm",
      "package": "@modelcontextprotocol/server-github",
      "version": "2025.4.8"
    },
    {
      "name": "fetch",
      "install_source": "pypi",
      "package": "mcp-server-fetch"
    },
    {
      "name": "internal-docs",
      "install_source": "remote_url",
      "url": "https://mcp.internal.example.com/sse"
    }
  ]
}
```

| Field | Required | Meaning |
|---|---|---|
| `version` | no (default `1`) | Format version. Only `1` is supported; any other value is rejected. |
| `servers` | yes | List of approved entries. |
| `servers[].name` | no | Server name as it appears in the MCP client config (the key under `mcpServers`). |
| `servers[].install_source` | no | Informational only: `npm`, `pypi`, `container`, `remote_url` or `local_path`. |
| `servers[].package` | no | npm or PyPI package name, or container image (without a version). |
| `servers[].version` | no | If set, the configured server must pin exactly this version. |
| `servers[].url` | no | Endpoint URL for remote (SSE / HTTP) servers. |

Unknown keys (such as `_comment`) are ignored.

### How servers are matched

A discovered server matches an entry when (comparisons ignore case):

1. its package, or its normalised URL (scheme, host and path; credentials and query string removed), equals the entry's; **or**
2. its name equals the entry's `name` **and** the entry does not name a *different* package or URL from the one configured. A server called `github` that runs an unrelated package is still flagged.

The match then gives one of these classifications:

| Classification | When |
|---|---|
| `approved` | Matches an entry, and either the entry has no `version` or the configured pin equals it. |
| `unknown-version` | Matches an entry that pins `version`, but the configured server pins a different version or none. |
| `unapproved` | Matches no entry. Each one raises **one HIGH finding** (`discover_unapproved_*`, OWASP ASI04 / MCP09). |
| `unchecked` | No allowlist was given. |

`axiom discover` exits with code 1 when an allowlist is given and at least one server is `unapproved`.

Over REST, send the same document inline as the `allowlist` field of `POST /api/v1/discover`.

---

## Threat rule catalogue

`axiom threatmodel` creates threats only by evaluating the rules in [`data/threat_catalogue.json`](../data/threat_catalogue.json) against the system model. To add or change a threat, edit the JSON; no code change is needed. The file is validated on load, and a bad rule stops the run with a clear `ValueError`.

### Top-level keys

| Key | Meaning |
|---|---|
| `catalogue_version` | Version string, shown in every report (`rule catalogue 0.5.0`). |
| `description` | Free text. |
| `maestro_layers` | The seven CSA MAESTRO layer names, keyed `"1"` to `"7"`. |
| `stride` | STRIDE letter to name (`S`, `T`, `R`, `I`, `D`, `E`). |
| `dsl` | Built-in documentation of the trigger language (summarised below). |
| `rules` | The list of rules. |

### Rule fields

```json
{
  "id": "TM-001",
  "title": "Exfiltration chain: untrusted content can drive an outbound tool",
  "description": "Written in our own words ...",
  "trigger": { "type": "tool_pair", "a": "reads_external", "b": "sends_out", "same_context": true },
  "evidence": { "categories": ["toxic_tool_combo", "data_exfiltration"], "id_prefixes": ["toxic_combo_"] },
  "stage": "impact",
  "stride": "I",
  "maestro_layer": 3,
  "cross_layer": [1, 2, 7],
  "owasp_asi": ["ASI01", "ASI02"],
  "owasp_mcp": ["MCP06", "MCP10"],
  "likelihood": 4,
  "impact": 4,
  "mitigations": [
    { "owner": "operator", "text": "Require human confirmation for outbound actions ..." }
  ]
}
```

| Field | Required | Rules |
|---|---|---|
| `id` | yes | Unique. Threat ids in the output are `<id>-<8 hex chars>`, derived from the affected components, so they are stable between runs. |
| `title`, `description` | yes | Text shown in the report. |
| `trigger` | yes | Object with a `type` (see below) and that type's filters. |
| `stride` | yes | One of `S`, `T`, `R`, `I`, `D`, `E`. |
| `maestro_layer` | yes | Integer 1-7 (primary layer). |
| `cross_layer` | yes | List of other layers (1-7) the threat spans. It may be empty. |
| `owasp_asi`, `owasp_mcp` | yes | Framework tags (lists, may be empty). |
| `likelihood`, `impact` | yes | Integers 1-5. |
| `mitigations` | yes | List of `{owner, text}`. `owner` is one of `developer`, `operator`, `platform` or `security_team`; the report groups mitigations by owner. |
| `evidence` | no | Selector `{categories, id_prefixes, id_contains}`. A scan finding attached to an affected component (or its server) that matches any of these is listed as evidence, and the threat's likelihood rises by 1 (max 5). |
| `stage` | no (default `pivot`) | `entry`, `pivot` or `impact`. Used to chain threats into attack paths (entry, then pivot, then impact). |

**Risk** = likelihood x impact (1-25). Bands: **critical** >= 20, **high** >= 12, **medium** >= 6, **low** below 6.

### Trigger types

| `type` | Fires |
|---|---|
| `component_attr` | Once per component of `kind` (string or list). Optional filters: `attr` (string or list; any listed attribute is truthy), `attr_all` (all truthy), `and_not` / `attr_missing` (attribute falsy or absent), `trust_zone` (string or list). |
| `tool_pair` | When, within one agent context (the same agent host, if `same_context` is true), some tool has capability `a` and some tool has capability `b`. Capabilities: `reads_external`, `sends_out`, `writes`, `executes`. Fires once per distinct set of contributing tools. |
| `flow` | Once per data flow matching all given filters: `crosses_boundary`, `data_class`, `src_kind`, `dst_kind`, `dst_trust_zone` (string or list), `dst_attr` (truthy), `dst_attr_missing` (falsy or absent). |
| `shared_credential` | Once per credential that flows (data class `secrets`) to two or more MCP servers. |
| `remote_agent` | Once per A2A remote agent. Optional `attr` (truthy; lists must be non-empty) and `attr_missing` (falsy or absent). |
| `remote_agent_skill_output` | Once per remote agent that advertises at least one skill and whose output flows back into an agent host. |
| `finding` | Raised directly from scan findings, matched by `categories` or `id_prefixes`, with an optional `severity` list. Grouped into one threat per set of affected components unless `per_finding` is true. `uncovered_only` keeps only findings that no other rule already used as evidence (these rules are evaluated last). |

### Vocabulary the triggers can refer to

- **Component kinds:** `agent_host`, `mcp_server`, `tool`, `resource`, `prompt`, `data_store`, `credential`, `external_service`, `remote_agent`
- **Data classes:** `user_prompt`, `tool_arguments`, `tool_results`, `secrets`, `files`, `external_content`, `delegation`
- **Trust zones:** `local_machine`, `third_party`, `remote_server`, `internet`
