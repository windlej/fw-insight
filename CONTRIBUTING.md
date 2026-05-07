# Contributing to fw-insight

## Development Setup

```bash
make dev       # Install Python + Node dependencies
make test      # Run tests
make lint      # Run linter + formatter
make typecheck # Run type checker
```

## Code Standards

- **Python**: Black formatting, Ruff linting, MyPy type checking
- **TypeScript**: ESLint + Prettier, strict mode
- **Commits**: Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`)

## Adding a New Vendor Parser

1. Create `parsers/<vendor>/` with `__init__.py`, `parser.py`, `normalizer.py`
2. Implement `VendorParser` interface (parse + normalize methods)
3. Register in `parsers/__init__.py`: `from parsers.<vendor> import <VendorParser>; register_parser(<VendorParser>)`
4. Add test fixtures in `parsers/<vendor>/tests/fixtures/`
5. Write tests in `parsers/<vendor>/tests/test_parser.py`

## Adding a New Analysis Check

1. Create `core/analysis/checks/<name>.py`
2. Use the `@check()` decorator with id, severity, title, description
3. Import in `core/analysis/checks/__init__.py` to register
4. Add tests that trigger and don't trigger the check

## Pull Requests

- Include tests for new functionality
- Run `make test && make lint` before submitting
- Update documentation if adding features
- Keep PRs focused — one feature/fix per PR
