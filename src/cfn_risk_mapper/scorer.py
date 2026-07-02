"""Exposure scorer stage: computes a declared_exposure_score (0.0-10.0) per
finding from resource type criticality, graph fan-out/fan-in, and
property-level exposure signals (open CIDRs, wildcard IAM, public buckets).

This is a static, in-template signal only -- never a live-AWS "blast radius".
"""


def score_finding(finding, graph):
    """Return the declared_exposure_score for a single Checkov finding."""
    raise NotImplementedError
