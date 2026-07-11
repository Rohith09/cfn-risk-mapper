from pathlib import Path

from cfn_risk_mapper.compliance_mapper import map_to_controls
from cfn_risk_mapper.detector import run_checkov

FIXTURE = Path(__file__).parent.parent / "fixtures" / "sample.json"


def test_map_to_controls_covers_every_check_id_the_fixture_produces():
    findings = run_checkov(FIXTURE)
    check_ids = {f["check_id"] for f in findings}

    for check_id in check_ids:
        assert map_to_controls(check_id), f"{check_id} has no NIST 800-53 mapping"


def test_map_to_controls_known_check():
    assert map_to_controls("CKV_AWS_63") == ["AC-6"]


def test_map_to_controls_unknown_check_returns_empty_list():
    assert map_to_controls("CKV_AWS_NOT_A_REAL_CHECK") == []
