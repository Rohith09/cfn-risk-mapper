"""CLI entrypoint. Thin click wrapper around the 5-stage pipeline."""

from pathlib import Path

import cfn_flip
import click
from rich.console import Console
from rich.table import Table

from cfn_risk_mapper.compliance_mapper import map_to_controls
from cfn_risk_mapper.detector import CheckovNotFoundError, run_checkov
from cfn_risk_mapper.graph_builder import build_graph
from cfn_risk_mapper.report_generator import generate_report
from cfn_risk_mapper.scorer import score_finding

console = Console()

_TEMPLATE_GLOBS = ("*.json", "*.yaml", "*.yml")


@click.group()
def cli():
    """cfn-risk-mapper: prioritize CloudFormation security findings by declared exposure."""


@cli.command()
@click.option(
    "--template",
    type=click.Path(exists=True, dir_okay=False),
    help="Path to a single CloudFormation template (JSON or YAML). Mutually exclusive with --template-dir.",
)
@click.option(
    "--template-dir",
    type=click.Path(exists=True, file_okay=False),
    help=(
        "Directory to recursively scan for CloudFormation templates (*.json, *.yaml, *.yml). "
        "Each template is scanned independently (its own graph and scores) -- this does not "
        "resolve Fn::ImportValue references across stacks. Mutually exclusive with --template."
    ),
)
@click.option(
    "--out",
    required=True,
    type=click.Path(),
    help="Path to write the generated Markdown report.",
)
@click.option(
    "--fail-on-score",
    type=float,
    default=None,
    help=(
        "Exit non-zero if any finding's declared_exposure_score is >= this value. "
        "For CI gating -- e.g. `--fail-on-score 7` blocks the pipeline on highly "
        "exposed findings while still writing the full report."
    ),
)
def scan(template, template_dir, out, fail_on_score):
    """Scan CloudFormation template(s) and generate a risk-prioritized report."""
    if bool(template) == bool(template_dir):
        raise click.UsageError("Provide exactly one of --template or --template-dir.")

    template_paths = _discover_template_paths(template, template_dir)

    findings = []
    for path in template_paths:
        findings.extend(_scan_one(path))

    if template_dir:
        report_label = f"{len(template_paths)} template(s) in {template_dir}"
    else:
        report_label = template

    generate_report(findings, out, template_path=report_label)

    _print_summary(findings, out)

    if fail_on_score is not None:
        breaching = [f for f in findings if f["declared_exposure_score"] >= fail_on_score]
        if breaching:
            console.print(
                f"[bold red]{len(breaching)} finding(s) at or above "
                f"declared_exposure_score {fail_on_score}[/bold red] -- failing the build."
            )
            raise SystemExit(1)


def _discover_template_paths(template, template_dir):
    if template:
        return [Path(template)]

    paths = sorted(
        {path for pattern in _TEMPLATE_GLOBS for path in Path(template_dir).rglob(pattern)}
    )
    if not paths:
        raise click.ClickException(f"No CloudFormation templates found under {template_dir}.")
    return paths


def _scan_one(path):
    try:
        template_dict, _ = cfn_flip.load(path.read_text())
    except Exception as exc:
        raise click.ClickException(f"Could not parse {path} as CloudFormation JSON/YAML: {exc}")

    try:
        findings = run_checkov(path)
    except (CheckovNotFoundError, RuntimeError) as exc:
        raise click.ClickException(f"{path}: {exc}")

    graph = build_graph(template_dict)
    for finding in findings:
        finding["declared_exposure_score"] = score_finding(finding, graph, template_dict)
        finding["controls"] = map_to_controls(finding["check_id"])

    return findings


def _print_summary(findings, out):
    console.print(f"[bold]{len(findings)}[/bold] finding(s) written to [cyan]{out}[/cyan]")

    if not findings:
        return

    top_findings = sorted(findings, key=lambda f: f["declared_exposure_score"], reverse=True)[:10]

    table = Table(title="Top findings by declared_exposure_score")
    table.add_column("Score", justify="right")
    table.add_column("Check")
    table.add_column("Resource")
    table.add_column("Type")
    table.add_column("Controls")

    for finding in top_findings:
        table.add_row(
            f"{finding['declared_exposure_score']:.1f}",
            f"{finding['check_id']} {finding['check_name']}",
            finding["logical_id"],
            finding["resource_type"],
            ", ".join(finding["controls"]) or "-",
        )

    console.print(table)


if __name__ == "__main__":
    cli()
