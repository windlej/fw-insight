"""Diff command."""

import json
import click

from parsers import get_parser
from core.normalizer import normalize
from core.diff import diff_sessions


@click.command()
@click.argument("file_a", type=click.Path(exists=True))
@click.argument("file_b", type=click.Path(exists=True))
@click.option("--vendor", required=True, help="Vendor type (e.g., paloalto)")
@click.option("--output", "-o", type=click.Path(), help="Output file (JSON)")
def diff(file_a, file_b, vendor, output):
    """Compare two firewall config files."""
    raw_a = open(file_a, "rb").read()
    raw_b = open(file_b, "rb").read()

    parser = get_parser(vendor)

    ast_a = parser.parse(raw_a)
    session_a_data = parser.normalize(ast_a)
    session_a = normalize(vendor, session_a_data, source_filename=file_a, source_content=raw_a)

    ast_b = parser.parse(raw_b)
    session_b_data = parser.normalize(ast_b)
    session_b = normalize(vendor, session_b_data, source_filename=file_b, source_content=raw_b)

    result = diff_sessions(session_a, session_b)

    if output:
        with open(output, "w") as f:
            json.dump(result.model_dump(), f, indent=2, default=str)
        click.echo(f"Diff written to {output}")
    else:
        click.echo(f"Added rules: {len(result.added_rules)}")
        click.echo(f"Removed rules: {len(result.removed_rules)}")
        click.echo(f"Modified rules: {len(result.modified_rules)}")
