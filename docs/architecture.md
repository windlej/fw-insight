# Architecture

## Overview

fw-insight is a local-only firewall configuration analysis platform. It parses vendor-specific firewall configs, normalizes them to a canonical data model, runs security analysis checks, and presents results via a web UI or CLI.

## Components

### Core Engine (`core/`)
- **Models**: Pydantic models defining the canonical data schema
- **Normalizer**: Converts vendor ASTs to canonical Session objects
- **Analysis Engine**: Orchestrates registered checks against sessions
- **IP Utils**: CIDR math and IP address utilities
- **Diff Engine**: Compares two sessions

### Parsers (`parsers/`)
Each vendor has an isolated parser package:
- `parser.py`: Extracts data from raw config into a vendor-specific AST
- `normalizer.py`: Maps the AST to canonical model fields
- `tests/`: Fixtures and unit tests

### API Server (`api/`)
- FastAPI server serving REST endpoints
- SQLite storage for sessions and findings
- Serves React static files in production

### CLI (`cli/`)
- Click-based CLI tool (`fw-insight`)
- Reuses core engine directly (no API dependency)
- Commands: analyze, report, diff, export, serve

### Web UI (`web/`)
- React + TypeScript SPA
- TanStack Query for data fetching
- TanStack Table + Virtual for large rule sets
- Served as static files from FastAPI

## Data Flow

1. User uploads config file (web) or specifies file (CLI)
2. Parser extracts vendor-specific data into AST
3. Normalizer converts AST to canonical Session
4. Analysis engine runs all registered checks
5. Results stored in SQLite (web) or output directly (CLI)
6. UI displays findings, policies, objects, comparison

## Design Principles

- Normalize intent, not syntax
- Prefer explicitness over magic
- Fail loudly but safely
- Keep vendor logic isolated
- Assume configs are messy
- Design for rule count growth
- Human-readable findings over raw data
