# Security policy

Axiom is a security scanner; we treat reports about Axiom itself with the seriousness we ask of others.

## Reporting a vulnerability

Email **contact@helionworks.com** with a description, the affected version (`axiom version`) and, if you can, a reproduction. Please do not open a public issue for anything that could be exploited.

- You will get an acknowledgement within 3 working days and a status update at least every 14 days.
- We ask for 90 days before public disclosure, or less once a fix has shipped.
- Credit is given in the changelog unless you ask otherwise.

## What is in scope

- The `axiom` CLI and the `app/` analysis code: anything that makes Axiom execute, fetch or leak something it should not, or that lets a scanned server influence the scanning machine.
- The promise that **Axiom never calls a tool** on a scanned server (`tools/call` is never sent; `live` only reads `initialize`, `tools/list`, `resources/list`, `resources/read`, `prompts/list`, `prompts/get` with the limits documented in the README). A way to make it call a tool is a vulnerability.
- The promise that the usage ping carries **counts only** (`axiom telemetry show` prints the exact payload). Any name, path or content reaching the endpoint is a vulnerability.
- The REST API under `app/api/` when deployed.

## What is not

- False negatives (a hostile server Axiom misses) and false positives are **detection issues**, not security vulnerabilities. Open a GitHub issue with the server or a minimal inert fixture; see `docs/COVERAGE.md` for how coverage is measured.
- Findings in third-party MCP servers Axiom reports on. Report those to their maintainers.

## Supported versions

Only the latest release on PyPI receives fixes.

© 2026 Helion Works.
