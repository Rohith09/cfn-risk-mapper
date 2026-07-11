from pathlib import Path

from click.testing import CliRunner

from cfn_risk_mapper.cli import cli

FIXTURE = Path(__file__).parent.parent / "fixtures" / "sample.json"


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output


def test_scan_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--template" in result.output
    assert "--out" in result.output


def test_scan_runs_the_full_pipeline_end_to_end(tmp_path):
    out_path = tmp_path / "report.md"
    runner = CliRunner()

    result = runner.invoke(cli, ["scan", "--template", str(FIXTURE), "--out", str(out_path)])

    assert result.exit_code == 0, result.output
    assert "finding(s) written to" in result.output

    report_text = out_path.read_text()
    assert "## AC -- Access Control" in report_text
    assert "BroadRole" in report_text
