from pathlib import Path

from click.testing import CliRunner

from cfn_risk_mapper.cli import cli

FIXTURE = Path(__file__).parent.parent / "fixtures" / "sample.json"
YAML_FIXTURE = Path(__file__).parent.parent / "fixtures" / "sample.yaml"
MULTI_STACK_DIR = Path(__file__).parent.parent / "fixtures" / "multi_stack"


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


def test_scan_fails_the_build_when_a_finding_meets_the_threshold(tmp_path):
    out_path = tmp_path / "report.md"
    runner = CliRunner()

    # BroadRole's wildcarded IAM policy scores 8.5 in the fixture.
    result = runner.invoke(
        cli, ["scan", "--template", str(FIXTURE), "--out", str(out_path), "--fail-on-score", "8.0"]
    )

    assert result.exit_code == 1
    assert "failing the build" in result.output
    # The report is still written even though the build is gated as failing.
    assert out_path.exists()


def test_scan_passes_when_nothing_meets_the_threshold(tmp_path):
    out_path = tmp_path / "report.md"
    runner = CliRunner()

    result = runner.invoke(
        cli, ["scan", "--template", str(FIXTURE), "--out", str(out_path), "--fail-on-score", "9.0"]
    )

    assert result.exit_code == 0, result.output


def test_scan_accepts_yaml_templates_with_short_form_intrinsics(tmp_path):
    out_path = tmp_path / "report.md"
    runner = CliRunner()

    result = runner.invoke(cli, ["scan", "--template", str(YAML_FIXTURE), "--out", str(out_path)])

    assert result.exit_code == 0, result.output
    report_text = out_path.read_text()
    # Same fixture content as sample.json, so the same findings should surface.
    assert "BroadRole" in report_text
    assert "## AC -- Access Control" in report_text


def test_scan_requires_exactly_one_of_template_or_template_dir(tmp_path):
    out_path = tmp_path / "report.md"
    runner = CliRunner()

    neither = runner.invoke(cli, ["scan", "--out", str(out_path)])
    assert neither.exit_code != 0
    assert "exactly one of --template or --template-dir" in neither.output

    both = runner.invoke(
        cli,
        ["scan", "--template", str(FIXTURE), "--template-dir", str(MULTI_STACK_DIR), "--out", str(out_path)],
    )
    assert both.exit_code != 0
    assert "exactly one of --template or --template-dir" in both.output


def test_scan_template_dir_aggregates_findings_from_every_file(tmp_path):
    out_path = tmp_path / "report.md"
    runner = CliRunner()

    result = runner.invoke(cli, ["scan", "--template-dir", str(MULTI_STACK_DIR), "--out", str(out_path)])

    assert result.exit_code == 0, result.output
    report_text = out_path.read_text()
    # Findings from both independently-scanned files should appear in one report.
    assert "OpenSshSecurityGroup" in report_text
    assert "PublicStorageBucket" in report_text
    assert "network.json" in report_text
    assert "storage.json" in report_text
