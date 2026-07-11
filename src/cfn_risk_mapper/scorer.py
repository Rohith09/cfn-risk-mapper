"""Exposure scorer stage: computes a declared_exposure_score (0.0-10.0) per
finding from resource type criticality, graph fan-out/fan-in, and
property-level exposure signals (open CIDRs, wildcard IAM, public buckets).

This is a static, in-template signal only -- never a live-AWS "blast radius".
"""

_TYPE_CRITICALITY = {
    "AWS::IAM::Role": 5,
    "AWS::IAM::Policy": 5,
    "AWS::IAM::User": 4,
    "AWS::S3::Bucket": 5,
    "AWS::S3::BucketPolicy": 5,
    "AWS::EC2::SecurityGroup": 4,
    "AWS::RDS::DBInstance": 4,
    "AWS::Lambda::Function": 3,
    "AWS::ApiGateway::RestApi": 4,
    "AWS::ElasticLoadBalancingV2::LoadBalancer": 4,
}
_DEFAULT_CRITICALITY = 2

_GRAPH_WEIGHT = 0.5
_SIGNAL_WEIGHT = 1.5
_MAX_SCORE = 10.0

_OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
_PUBLIC_ACLS = {"PublicRead", "PublicReadWrite"}


def score_finding(finding, graph, template):
    """Return the declared_exposure_score (0.0-10.0) for a single finding.

    Combines resource type criticality, the resource's fan-in/fan-out in
    `graph` (how many other declared resources reference it or it
    references), and property-level exposure signals read directly from
    `template` (open CIDRs, wildcard IAM actions/resources, public bucket
    ACLs/policies).
    """
    logical_id = finding["logical_id"]
    criticality = _TYPE_CRITICALITY.get(finding["resource_type"], _DEFAULT_CRITICALITY)

    if logical_id in graph:
        graph_score = (graph.in_degree(logical_id) + graph.out_degree(logical_id)) * _GRAPH_WEIGHT
    else:
        graph_score = 0

    resource = template.get("Resources", {}).get(logical_id, {})
    signal_score = len(_exposure_signals(resource.get("Properties", {}))) * _SIGNAL_WEIGHT

    return round(min(criticality + graph_score + signal_score, _MAX_SCORE), 1)


def _exposure_signals(properties):
    """Return the set of distinct exposure-signal names found in properties."""
    signals = set()
    _scan(properties, signals)
    return signals


def _scan(node, signals):
    if isinstance(node, dict):
        if _contains_wildcard(node.get("Action")):
            signals.add("wildcard_iam_action")

        if _contains_wildcard(node.get("Resource")):
            signals.add("wildcard_iam_resource")

        if node.get("CidrIp") in _OPEN_CIDRS or node.get("CidrIpv6") in _OPEN_CIDRS:
            signals.add("open_cidr")

        if node.get("AccessControl") in _PUBLIC_ACLS:
            signals.add("public_bucket_acl")

        principal = node.get("Principal")
        if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
            signals.add("public_principal")

        for value in node.values():
            _scan(value, signals)

    elif isinstance(node, list):
        for item in node:
            _scan(item, signals)


def _contains_wildcard(value):
    return value == "*" or (isinstance(value, list) and "*" in value)
