"""Report generator stage: renders a Jinja2 Markdown report, findings grouped
by NIST control family and ranked by declared_exposure_score within each group.
"""

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

_TEMPLATES_DIR = Path(__file__).parent / "templates"

_FAMILY_NAMES = {
    "AC": "Access Control",
    "AU": "Audit and Accountability",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IA": "Identification and Authentication",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
}


def generate_report(findings, out_path, template_path=None):
    """Render findings to a Markdown report at out_path.

    Each finding must already carry `declared_exposure_score` (from the
    scorer stage) and `controls` (a list of NIST 800-53 control IDs from
    the compliance mapper stage, possibly empty). Findings are grouped by
    the family of their first-listed control and ranked by
    declared_exposure_score within each group; findings with no mapped
    control are listed separately under "Unmapped findings".
    """
    groups, unmapped = _group_by_control_family(findings)

    env = Environment(loader=FileSystemLoader(_TEMPLATES_DIR), trim_blocks=True, lstrip_blocks=True)
    template = env.get_template("report.md.j2")
    rendered = template.render(
        template_path=template_path,
        total_findings=len(findings),
        groups=groups,
        unmapped=unmapped,
    )

    Path(out_path).write_text(rendered)


def _group_by_control_family(findings):
    by_family = {}
    unmapped = []

    for finding in findings:
        controls = finding.get("controls") or []
        if not controls:
            unmapped.append(finding)
            continue

        family_code = controls[0].split("-", 1)[0]
        by_family.setdefault(family_code, []).append(finding)

    groups = [
        {
            "family_code": code,
            "family_name": _FAMILY_NAMES.get(code, code),
            "findings": sorted(fs, key=lambda f: f["declared_exposure_score"], reverse=True),
        }
        for code, fs in sorted(by_family.items())
    ]
    unmapped.sort(key=lambda f: f["declared_exposure_score"], reverse=True)

    return groups, unmapped
