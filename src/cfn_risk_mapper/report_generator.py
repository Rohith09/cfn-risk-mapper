"""Report generator stage: renders a Jinja2 Markdown report, findings grouped
by NIST control family and ranked by declared_exposure_score within each group.
"""


def generate_report(findings, out_path):
    """Render findings to a Markdown report at out_path."""
    raise NotImplementedError
