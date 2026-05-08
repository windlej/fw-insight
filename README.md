# fw-insight

Firewall configuration visualization and analysis platform. Parse, normalize, analyze, and visualize firewall configs from multiple vendors.

## Quick Start

```bash
# Build and run with Docker
docker compose up

# Open http://localhost:8080
```

## Features

- **Multi-vendor support**: Palo Alto (XML), FortiGate (CLI), Cisco ASA/Firepower (CLI), UniFi (controller + gateway)
- **Security analysis**: Detects any-any rules, internet exposure, large CIDRs, missing logging, shadowed/redundant rules
- **Interactive web UI**: Dashboard, policy tables, drill-down views, side-by-side comparison
- **CLI mode**: `fw-insight analyze`, `fw-insight report`, `fw-insight diff`, `fw-insight export`
- **PDF reports**: Export analysis results as readable PDF reports
- **Offline-first**: Fully local, no external API calls, all data stored locally

## CLI Usage

```bash
# Analyze a config
fw-insight analyze config.xml --vendor paloalto

# Generate PDF report
fw-insight report config.xml --vendor paloalto --format pdf --output report.pdf

# Compare two configs
fw-insight diff old.xml new.xml --vendor paloalto

# Export canonical JSON
fw-insight export config.xml --vendor paloalto --format json --output model.json

# Start web server
fw-insight serve --host 0.0.0.0 --port 8080
```

## Development

```bash
# Install dependencies
make dev

# Run tests
make test

# Lint
make lint

# Build Docker image
make docker-build
```

## Architecture

```
User → Web UI / CLI
         │
         ▼
    FastAPI Server
         │
    ┌────┴────┐
    │         │
  Engine   SQLite
    │
  ┌─┴──────────┐
  │            │
Parser      Analyzer
(PA, FG,   (checks:
 ASA,       any-any,
 UniFi)     exposure,
            ...)
```

## Supported Vendors

| Vendor | Format | Status |
|--------|--------|--------|
| Palo Alto | XML export | Implemented |
| FortiGate | CLI config | Implemented |
| Cisco ASA / Firepower | CLI config | Implemented |
| UniFi Controller | .unf backup | Planned |
| UniFi Gateway | Vyatta CLI | Planned |

## License

Apache 2.0
