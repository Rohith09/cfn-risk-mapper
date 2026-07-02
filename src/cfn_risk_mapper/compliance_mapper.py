"""Compliance mapper stage: static YAML lookup mapping Checkov check IDs to
NIST 800-53 control IDs. Hand-verified (20-30 entries), not bulk-generated.
"""


def map_to_controls(check_id):
    """Return the NIST 800-53 control IDs mapped to a Checkov check ID."""
    raise NotImplementedError
