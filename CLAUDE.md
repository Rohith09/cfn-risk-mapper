# cfn-risk-mapper

Python CLI portfolio project (for Cloud Security Architect job applications) that wraps
Checkov to prioritize CloudFormation security findings by declared exposure and maps
them to NIST 800-53 controls. Code quality and defensible design decisions matter more
than speed or feature density.

## Problem

Checkov and similar scanners flag every misconfiguration with equal visual weight. A
scan can return 50+ findings with no sense of which ones actually matter given how
resources connect to each other. This tool adds a synthesis layer on top of Checkov's
detection.

## Hard scope constraints -- do not scope-creep into these

- **Never reimplement CloudFormation security rule detection.** Always shell out to
  `checkov -f <template> -o json` for that.
- **The score is always called `declared_exposure_score`, never "blast radius."** It is
  computed only from what's declared in the template(s) given (Ref, Fn::GetAtt,
  DependsOn, Fn::Sub interpolation) -- not live AWS state. Docs and CLI output must be
  explicit about this distinction.
- **No AWS credentials, no live account access.** Pure static analysis.
- **CloudFormation JSON and YAML are both supported** (short-form intrinsics like
  `!Ref`/`!GetAtt` included) -- `cfn_flip.load()` normalizes either into the same
  long-form dict `graph_builder.py` expects. Checkov itself already handles both
  formats natively, so `detector.py` needed no changes for this.
- **No web app, no database, no hosting.** A shell script wraps a Python CLI; output is
  a generated static Markdown report file. Nothing to deploy.
- **Directory scanning is independent per-file, not cross-stack.** `--template-dir`
  scans every template under a directory and combines findings into one report, but
  each template gets its own graph/scores -- no `Fn::ImportValue` resolution across
  stacks. That remains a stretch goal, not implemented.

## Architecture (5 stages, keep as clearly separated modules)

1. **Input** -- `cli.py` accepts either `--template <file>` (JSON or YAML) or
   `--template-dir <dir>` (recursively scans *.json/*.yaml/*.yml, each independently).
   Cross-stack `Fn::ImportValue` resolution remains a stretch goal.
2. **Detection** (`detector.py`) -- subprocess call to `checkov -f <template> -o json`,
   parse findings.
3. **Graph builder** (`graph_builder.py`) -- parse the template's `Resources` block
   directly, build a networkx `DiGraph` from Ref/GetAtt/DependsOn/Sub references
   between resources. No external tool needed -- CFN templates declare this natively.
4. **Exposure scorer** (`scorer.py`) -- for each Checkov finding, compute a
   `declared_exposure_score`: weight by resource type criticality, fan-out/fan-in count
   in the graph, and property-level exposure signals (0.0.0.0/0 CIDRs, wildcard IAM
   actions/resources, public bucket policies).
5. **Compliance mapper** (`compliance_mapper.py`) -- static YAML lookup table mapping
   Checkov check IDs to NIST 800-53 control IDs (20-30 hand-verified mappings, not
   bulk-generated).
6. **Report generator** (`report_generator.py`) -- Jinja2 template producing a single
   Markdown file, findings grouped by control family, ranked by exposure score within
   each group.

`cli.py` is the click entrypoint (thin -- validates args, wires stages together).

## Tech stack

Python 3.14+, click (CLI), networkx (graph), rich (terminal output), Jinja2 (report
templating), pytest (tests). `scan.sh` is a thin wrapper: activates a venv if present,
then calls `python -m cfn_risk_mapper.cli scan "$@"`. No logic in bash.

## Test fixture

`fixtures/sample.json` -- three intentionally misconfigured resources used to test
each stage as it's built:
- `BroadRole` -- IAM role with wildcard `Action: "*"` / `Resource: "*"` policy
- `DataBucket` -- S3 bucket with `PublicRead` access control
- `ProcessorFunction` -- Lambda referencing `BroadRole` via `Fn::GetAtt`, `DataBucket`
  via `Ref` (in an env var) and `Fn::Sub` (in inline code), plus an explicit
  `DependsOn: DataBucket`

`fixtures/sample.yaml` -- YAML twin of `sample.json` using short-form intrinsics
(`!GetAtt`, `!Ref`, `!Sub`), exercises YAML template support end-to-end.

`fixtures/multi_stack/` -- two small independent templates (`network.json` with an
open-ingress security group, `storage.json` with a public S3 bucket), used to test
`--template-dir` aggregation.

## Current state

v1 pipeline is fully wired and working end-to-end, including JSON/YAML and
single-file/directory input. `pytest` passes (24 tests across all stages).

- `detector.py` -- `run_checkov` shells out to Checkov, returns failed findings with
  `resource_type`/`logical_id` split out. Unchanged for YAML support -- Checkov
  already handles CFN YAML natively, we just pass the original file path through.
- `graph_builder.py` -- `build_graph` walks Ref/Fn::GetAtt/Fn::Sub/DependsOn into a
  networkx DiGraph (edge A -> B means "A references B").
- `scorer.py` -- `score_finding(finding, graph, template)` (note: takes `template` too,
  not just `graph`, since property-level signals need the resource's actual
  `Properties`) combines type criticality, graph fan-in/out, and exposure signals into
  `declared_exposure_score` (0.0-10.0).
- `compliance_mapper.py` -- `map_to_controls` reads a hand-verified YAML table
  (`data/nist_800_53_mappings.yaml`, 44 entries) of Checkov check ID -> NIST 800-53
  control IDs. Expanded from the initial 29 after testing against a real multi-tier
  template surfaced 15 more check IDs with no mapping.
- `report_generator.py` -- renders `templates/report.md.j2` via Jinja2, grouping by the
  2-letter NIST family code of each finding's first-listed control, ranked by
  `declared_exposure_score` within each group; unmapped findings get their own section.
  Resource name and type are separate table columns (not combined "Name (Type)").
- `cli.py` -- accepts `--template` (single file) or `--template-dir` (recursive,
  independent per-file scan, findings combined into one report); loads templates via
  `cfn_flip.load()` so JSON and YAML both normalize to the same long-form dict; supports
  `--fail-on-score` to exit non-zero for CI gating; prints a rich summary table of the
  top 10 findings to the terminal in addition to writing the report file.

Next candidates: cross-stack `Fn::ImportValue` resolution (the remaining stretch
goal), further expanding the NIST mapping table as new real-world templates surface
gaps, or a sample GitHub Actions workflow file committed to the repo.

Checkov is installed via `pipx` (`pipx install checkov`), not as a project dependency:
Checkov pins `networkx<2.7`, which conflicts with the `networkx>=3.2` this project
needs for `graph_builder.py`. This is fine because `detector.py` only ever shells out
to the `checkov` binary as a subprocess -- it's never imported as a library -- so its
dependencies don't need to share our venv.

Public GitHub repo is live at github.com/Rohith09/cfn-risk-mapper (MIT licensed).
