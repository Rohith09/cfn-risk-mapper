"""CLI entrypoint. Thin click wrapper around the 5-stage pipeline."""

import click


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
    click.echo(f"Would scan {template} and write report to {out} (pipeline not yet implemented).")


if __name__ == "__main__":
    cli()
