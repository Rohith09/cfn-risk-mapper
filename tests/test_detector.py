from pathlib import Path

import pytest

from cfn_risk_mapper.detector import CheckovNotFoundError, run_checkov

FIXTURE = Path(__file__).parent.parent / "fixtures" / "sample.json"


def test_run_checkov_returns_failed_findings():
    findings = run_checkov(FIXTURE)

    assert len(findings) > 0
    assert all("check_id" in f for f in findings)


def test_run_checkov_splits_resource_type_and_logical_id():
    findings = run_checkov(FIXTURE)

    broad_role_findings = [f for f in findings if f["logical_id"] == "BroadRole"]
    assert broad_role_findings
    assert broad_role_findings[0]["resource_type"] == "AWS::IAM::Role"


def test_run_checkov_raises_when_checkov_missing(monkeypatch):
    monkeypatch.setattr("cfn_risk_mapper.detector.shutil.which", lambda _: None)

    with pytest.raises(CheckovNotFoundError):
        run_checkov(FIXTURE)
