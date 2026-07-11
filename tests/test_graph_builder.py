import json
from pathlib import Path

from cfn_risk_mapper.graph_builder import build_graph

FIXTURE = Path(__file__).parent.parent / "fixtures" / "sample.json"


def _load_fixture():
    return json.loads(FIXTURE.read_text())


def test_build_graph_has_a_node_per_resource_with_its_type():
    graph = build_graph(_load_fixture())

    assert set(graph.nodes) == {"BroadRole", "DataBucket", "ProcessorFunction"}
    assert graph.nodes["BroadRole"]["resource_type"] == "AWS::IAM::Role"
    assert graph.nodes["DataBucket"]["resource_type"] == "AWS::S3::Bucket"
    assert graph.nodes["ProcessorFunction"]["resource_type"] == "AWS::Lambda::Function"


def test_build_graph_captures_getatt_ref_sub_and_dependson():
    graph = build_graph(_load_fixture())

    # ProcessorFunction -> BroadRole via Fn::GetAtt
    assert graph.has_edge("ProcessorFunction", "BroadRole")
    # ProcessorFunction -> DataBucket via Ref, Fn::Sub, and DependsOn (one edge, not three)
    assert graph.has_edge("ProcessorFunction", "DataBucket")
    assert graph.out_degree("ProcessorFunction") == 2


def test_build_graph_fan_in_reflects_how_many_resources_reference_a_node():
    graph = build_graph(_load_fixture())

    assert graph.in_degree("DataBucket") == 1
    assert graph.in_degree("BroadRole") == 1
    assert graph.in_degree("ProcessorFunction") == 0
