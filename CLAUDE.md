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
- **v1 accepts CloudFormation JSON only, not YAML.** YAML's short-form intrinsics
  (`!Ref`, `!GetAtt`) need cfn-flip or similar to normalize first -- deferred to v1.1.
- **No web app, no database, no hosting.** A shell script wraps a Python CLI; output is
  a generated static Markdown report file. Nothing to deploy.
- **Single-template scope.** Directory support for multi-stack `Fn::ImportValue`
  resolution is a stretch goal, not v1.

## Architecture (5 stages, keep as clearly separated modules)

1. **Input** -- path to a single CFN JSON template, handled in `cli.py`. Directory
   support is a stretch goal.
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

## Current state

Skeleton complete: all stage modules exist as stubs (`NotImplementedError`), CLI has a
working `scan` command (`--template`, `--out`) that doesn't yet run the pipeline, tests
cover `--help` output. venv created with Python 3.14 (via `brew install python@3.14`),
deps installed, `pytest` passes. Next: implement Stage 2 (`detector.py`).

Checkov is installed via `pipx` (`pipx install checkov`), not as a project dependency:
Checkov pins `networkx<2.7`, which conflicts with the `networkx>=3.2` this project
needs for `graph_builder.py`. This is fine because `detector.py` only ever shells out
to the `checkov` binary as a subprocess -- it's never imported as a library -- so its
dependencies don't need to share our venv.

Public GitHub repo is live at github.com/Rohith09/cfn-risk-mapper (MIT licensed).
