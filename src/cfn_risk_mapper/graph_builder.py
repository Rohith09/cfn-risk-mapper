"""Graph builder stage: parses a template's Resources block into a networkx
DiGraph of Ref / Fn::GetAtt / DependsOn / Fn::Sub relationships between
resources. No external tool needed -- CFN templates declare this natively.
"""


def build_graph(template):
    """Build a networkx DiGraph representing declared resource relationships."""
    raise NotImplementedError
