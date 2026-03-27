**SwaggerHunter** — Swagger/OpenAPI enumerator, exporter and conservative endpoint probe.

SwaggerHunter automatically parses Swagger/OpenAPI specs (JSON or YAML), resolves local $ref references, enumerates path templates, and can export or probe endpoints. It includes an interactive TUI (requires `rich`) and CLI with options for safe probing, unauthenticated bypass testing, and realistic payload generation via `Faker` when available.

What's New / Highlights
- Resolves local `$ref` and expands `components.pathItems` so nested or referenced path items are enumerated.
- Optional realistic request payloads using `Faker` (when installed) for better probe coverage.
- Conservative probing with Safe Mode (skip non-safe methods), retry/backoff, delay, concurrency, proxy and extra headers.
- Unauthenticated bypass detection: when a bearer token is used you can test whether the endpoint is accessible without it (`--test-unauth`).
- Scans response bodies for common sensitive patterns (password, api key, tokens) and reports hits.
- Interactive TUI: scope selection, keyword filters, per-endpoint drilldown, export to JSON/Postman/Burp, and saving probe results.

Features
- Fetch Swagger/OpenAPI spec from URL or local `file://` path (JSON/YAML).
- Deep `$ref` resolution and component pathItem expansion.
- Enumerate endpoints with path templates and generated example URLs.
- Export enumerated endpoints to JSON, Postman (v2.1), or Burp XML.
- Optional conservative probing with configurable concurrency, delay, timeout, retries, and safe-mode.
- Test for unauthenticated bypasses (`--test-unauth`).
- Scan responses for sensitive data patterns and surface findings.
- Support for proxies and custom headers (`--proxy`, `--header KEY:VAL`).
- Interactive TUI with `rich` (if installed): filtering, scope management, exports, and probe dashboards.

Requirements
- Python 3.8+
- See `requirements.txt` for core deps. Optional features:
  - `pyyaml` for YAML specs
  - `faker` for realistic payload generation
  - `rich` for the interactive TUI

Quick Start
1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. CLI examples
- Enumerate and print a summary:

```bash
python3 swaggerhunter.py -u 'http://IP:PORT/swagger/v1/swagger.json'
```

- Enumerate and export Postman collection:

```bash
python3 swaggerhunter.py -u 'http://IP:PORT/swagger/v1/swagger.json' --postman collection.json
```

- Probe endpoints (safe mode enabled to skip destructive methods):

```bash
python3 swaggerhunter.py -u 'http://IP:PORT/swagger/v1/swagger.json' --probe --safe-mode
```

- Probe with bearer token and test unauthenticated bypasses:

```bash
python3 swaggerhunter.py -u 'http://IP:PORT/swagger/v1/swagger.json' --probe --token 'TOKEN' --test-unauth
```

- Limit and method filters, plus saving JSON output:

```bash
python3 swaggerhunter.py -u 'http://IP:PORT/swagger/v1/swagger.json' --limit 50 --method GET --output endpoints.json
```

Interactive Mode (TUI)

```bash
python3 swaggerhunter.py
```

The TUI supports scope selection, keyword filtering, threaded probing, exports to Postman/Burp/JSON, and saving probe results.

Next steps
- If you'd like, I can further improve the README with a full CLI reference of flags and screenshots, or add a short examples section showing typical workflows for bug-bounty recon.

Support
If my tool helped you land a bug bounty, consider buying me a coffee ☕️ as a small thank-you!
