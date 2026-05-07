# CLI Reference

## Commands

### `fw-insight analyze`

Parse, normalize, and analyze a firewall config file.

```bash
fw-insight analyze <file> --vendor <vendor> [--output <file>] [--exit-on-severity <level>]
```

Options:
- `--vendor`: Vendor type (paloalto, fortinet, unifi_controller, unifi_gateway)
- `--output, -o`: Write findings to JSON file
- `--exit-on-severity`: Exit code 1 if any finding meets this severity (critical/high/medium/low)

### `fw-insight report`

Generate a PDF or JSON report.

```bash
fw-insight report <file> --vendor <vendor> [--format pdf|json] [--output <file>]
```

### `fw-insight diff`

Compare two config files.

```bash
fw-insight diff <file-a> <file-b> --vendor <vendor> [--output <file>]
```

### `fw-insight export`

Export config as canonical JSON.

```bash
fw-insight export <file> --vendor <vendor> [--output <file>]
```

### `fw-insight serve`

Start the web server.

```bash
fw-insight serve [--host <host>] [--port <port>]
```

Default: `http://127.0.0.1:8080`
