# cfn-risk-mapper

A CLI tool that wraps [Checkov](https://www.checkov.io/) to prioritize CloudFormation
security findings by **declared exposure** and maps them to NIST 800-53 controls.

## Problem

Checkov and similar scanners flag every misconfiguration with equal visual weight. A
scan can return 50+ findings with no sense of which ones actually matter given how
resources connect to each other. `cfn-risk-mapper` adds a synthesis layer on top of
Checkov's detection: it builds a graph of how resources in your template reference
each other, scores each finding by how exposed that resource is *within the template*,
and groups the results by the NIST 800-53 control family they map to.

## What this is not

- **Not a scanner.** It never reimplements CloudFormation security rule detection --
  it always shells out to Checkov for that.
- **Not a blast-radius calculator.** The `declared_exposure_score` is computed only
  from what's declared in the template(s) given (`Ref`, `Fn::GetAtt`, `DependsOn`,
  `Fn::Sub` interpolation) -- not live AWS state.
- **Not connected to your AWS account.** No credentials, no live account access. Pure
  static analysis.

## Status

Early development. v1 targets CloudFormation **JSON** templates only (YAML support is
deferred to v1.1). See [CLAUDE.md](CLAUDE.md) for the full architecture and scope
decisions.

## Requirements

- Python 3.14+
- [Checkov](https://www.checkov.io/) installed and on your `PATH`

Checkov is a separate CLI dependency, not a Python package of this project -- it pins
an old `networkx` that conflicts with the modern API `graph_builder.py` relies on.
Install it in its own isolated environment with [pipx](https://pipx.pypa.io/):

```bash
pipx install checkov
```

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
./scan.sh --template path/to/template.json --out report.md
```

## License

[MIT](LICENSE)
