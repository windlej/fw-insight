"""Analyze command."""

import json
import click

from parsers import get_parser
from core.normalizer import normalize
from core.analysis.engine import AnalysisEngine
from cli.output import print_findings_summary


@click.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--vendor", required=True, help="Vendor type (e.g., paloalto)")
@click.option("--output", "-o", type=click.Path(), help="Output file (JSON)")
@click.option("--exit-on-severity", type=click.Choice(["critical", "high", "medium", "low"]),
              help="Exit with code 1 if any finding meets this severity")
def analyze(file, vendor, output, exit_on_severity):
    """Analyze a firewall config file."""
    raw_content = open(file, "rb").read()

    parser = get_parser(vendor)
    ast = parser.parse(raw_content)
    session_data = parser.normalize(ast)

    session = normalize(vendor, session_data, source_filename=file, source_content=raw_content)

    engine = AnalysisEngine()
    result = engine.analyze(session)

    if output:
        output_data = {
            "session_id": session.id,
            "vendor": vendor,
            "hostname": session.hostname,
            "rule_count": session.rule_count,
            "health_score": result.health_score,
            "finding_counts": result.finding_counts,
            "findings": [f.model_dump() for f in result.findings],
        }
        with open(output, "w") as f:
            json.dump(output_data, f, indent=2, default=str)
        click.echo(f"Results written to {output}")
    else:
        print_findings_summary(result, session)

    if exit_on_severity:
        severity_order = ["critical", "high", "medium", "low"]
        threshold = severity_order.index(exit_on_severity)
        for finding in result.findings:
            if severity_order.index(finding.severity.value) <= threshold:
                click.echo(f"\nFinding at or above {exit_on_severity} severity detected.", err=True)
                raise SystemExit(1)
