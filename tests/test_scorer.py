import json
from pathlib import Path

from cfn_risk_mapper.detector import run_checkov
from cfn_risk_mapper.graph_builder import build_graph
from cfn_risk_mapper.scorer import score_finding

FIXTURE = Path(__file__).parent.parent / "fixtures" / "sample.json"


def _load_fixture():
    return json.loads(FIXTURE.read_text())


def _finding_for(logical_id):
    findings = run_checkov(FIXTURE)
    return next(f for f in findings if f["logical_id"] == logical_id)


def test_score_finding_stays_within_bounds():
    template = _load_fixture()
    graph = build_graph(template)

    score = score_finding(_finding_for("BroadRole"), graph, template)

    assert 0.0 <= score <= 10.0


def test_score_finding_ranks_fully_wildcarded_role_above_public_bucket():
    template = _load_fixture()
    graph = build_graph(template)

    broad_role_score = score_finding(_finding_for("BroadRole"), graph, template)
    data_bucket_score = score_finding(_finding_for("DataBucket"), graph, template)

    # BroadRole has both a wildcard Action and a wildcard Resource (two
    # signals); DataBucket only has one (public ACL) -- it should rank lower.
    assert broad_role_score > data_bucket_score


def test_score_finding_uses_default_criticality_for_unknown_resource_type():
    template = _load_fixture()
    graph = build_graph(template)
    finding = {"logical_id": "Nonexistent", "resource_type": "AWS::Made::Up"}

    score = score_finding(finding, graph, template)

    assert score == 2.0
