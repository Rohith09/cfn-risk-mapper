"""Compliance mapper stage: static YAML lookup mapping Checkov check IDs to
NIST 800-53 control IDs. Hand-verified (20-30 entries), not bulk-generated.
"""

from pathlib import Path

import yaml

_MAPPINGS_PATH = Path(__file__).parent / "data" / "nist_800_53_mappings.yaml"

with open(_MAPPINGS_PATH) as _f:
    _MAPPINGS = yaml.safe_load(_f)


def map_to_controls(check_id):
    """Return the NIST 800-53 control IDs mapped to a Checkov check ID.

    Returns an empty list if the check has no hand-verified mapping yet.
    """
    entry = _MAPPINGS.get(check_id)
    return entry["controls"] if entry else []
