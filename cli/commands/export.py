"""Export command."""

import json

import click

from core.normalizer import normalize
from parsers import get_parser


@click.command("export")
@click.argument("file", type=click.Path(exists=True))
@click.option("--vendor", required=True, help="Vendor type (e.g., paloalto)")
@click.option("--output", "-o", type=click.Path(), help="Output file (JSON)")
def export_cmd(file, vendor, output):
    """Export a firewall config as canonical JSON."""
    raw_content = open(file, "rb").read()

    parser = get_parser(vendor)
    ast = parser.parse(raw_content)
    session_data = parser.normalize(ast)

    session = normalize(vendor, session_data, source_filename=file, source_content=raw_content)

    output_path = output or "fw-insight-export.json"
    with open(output_path, "w") as f:
        json.dump(session.model_dump(), f, indent=2, default=str)

    click.echo(f"Canonical model written to {output_path}")
