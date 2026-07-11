"""CLI entrypoint. Thin click wrapper around the 5-stage pipeline."""

import json

import click
from rich.console import Console
from rich.table import Table

from cfn_risk_mapper.compliance_mapper import map_to_controls
from cfn_risk_mapper.detector import CheckovNotFoundError, run_checkov
from cfn_risk_mapper.graph_builder import build_graph
from cfn_risk_mapper.report_generator import generate_report
from cfn_risk_mapper.scorer import score_finding

console = Console()


@click.group()
def cli():
    """cfn-risk-mapper: prioritize CloudFormation security findings by declared exposure."""


@cli.command()
@click.option(
    "--template",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to a CloudFormation JSON template.",
)
@click.option(
    "--out",
    required=True,
    type=click.Path(),
    help="Path to write the generated Markdown report.",
)
def scan(template, out):
    """Scan a CloudFormation template and generate a risk-prioritized report."""
    with open(template) as f:
        template_dict = json.load(f)

    try:
        findings = run_checkov(template)
    except (CheckovNotFoundError, RuntimeError) as exc:
        raise click.ClickException(str(exc))

    graph = build_graph(template_dict)
    for finding in findings:
        finding["declared_exposure_score"] = score_finding(finding, graph, template_dict)
        finding["controls"] = map_to_controls(finding["check_id"])

    generate_report(findings, out, template_path=template)

    _print_summary(findings, out)


def _print_summary(findings, out):
    console.print(f"[bold]{len(findings)}[/bold] finding(s) written to [cyan]{out}[/cyan]")

    if not findings:
        return

    top_findings = sorted(findings, key=lambda f: f["declared_exposure_score"], reverse=True)[:10]

    table = Table(title="Top findings by declared_exposure_score")
    table.add_column("Score", justify="right")
    table.add_column("Check")
    table.add_column("Resource")
    table.add_column("Controls")

    for finding in top_findings:
        table.add_row(
            f"{finding['declared_exposure_score']:.1f}",
            f"{finding['check_id']} {finding['check_name']}",
            f"{finding['logical_id']} ({finding['resource_type']})",
            ", ".join(finding["controls"]) or "-",
        )

    console.print(table)


if __name__ == "__main__":
    cli()
