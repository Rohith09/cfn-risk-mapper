"""Detection stage: shells out to Checkov and parses its JSON findings.

Never reimplements CloudFormation security rule detection directly.
"""

import json
import shutil
import subprocess


class CheckovNotFoundError(RuntimeError):
    """Raised when the `checkov` executable isn't on PATH."""


def run_checkov(template_path):
    """Run `checkov -f <template_path> -o json` and return failed findings.

    Each finding is Checkov's own finding dict, plus `resource_type` and
    `logical_id` split out of Checkov's `"Type.LogicalId"` resource string
    so later stages can match findings to graph nodes without re-parsing it.
    """
    if shutil.which("checkov") is None:
        raise CheckovNotFoundError(
            "checkov not found on PATH. Install it with `pipx install checkov`."
        )

    # Checkov exits 1 whenever it has failed checks -- that's expected, not
    # an error, so we don't check the return code, only whether stdout parses.
    result = subprocess.run(
        ["checkov", "-f", str(template_path), "-o", "json"],
        capture_output=True,
        text=True,
    )

    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"checkov did not return valid JSON: {result.stderr.strip()}"
        ) from exc

    parsing_errors = parsed["results"].get("parsing_errors")
    if parsing_errors:
        raise RuntimeError(f"checkov failed to parse the template: {parsing_errors}")

    findings = []
    for finding in parsed["results"]["failed_checks"]:
        resource_type, _, logical_id = finding["resource"].partition(".")
        findings.append({**finding, "resource_type": resource_type, "logical_id": logical_id})
    return findings
