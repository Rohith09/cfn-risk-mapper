"""Detection stage: shells out to Checkov and parses its JSON findings.

Never reimplements CloudFormation security rule detection directly.
"""


def run_checkov(template_path):
    """Run `checkov -f <template_path> -o json` and return parsed findings."""
    raise NotImplementedError
