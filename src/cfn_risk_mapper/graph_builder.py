"""Graph builder stage: parses a template's Resources block into a networkx
DiGraph of Ref / Fn::GetAtt / DependsOn / Fn::Sub relationships between
resources. No external tool needed -- CFN templates declare this natively.
"""

import re

import networkx as nx

_SUB_TOKEN_RE = re.compile(r"\$\{([^}!]+)\}")


def build_graph(template):
    """Build a networkx DiGraph representing declared resource relationships.

    Nodes are resource logical IDs, tagged with a `resource_type` attribute.
    An edge `A -> B` means "A declares a reference to B" (via Ref, Fn::GetAtt,
    Fn::Sub interpolation, or DependsOn), so B's in-degree is how many other
    resources point at it and A's out-degree is how many it points at.
    """
    resources = template.get("Resources", {})
    graph = nx.DiGraph()

    for logical_id, resource in resources.items():
        graph.add_node(logical_id, resource_type=resource.get("Type"))

    for logical_id, resource in resources.items():
        for target in _referenced_logical_ids(resource, resources):
            if target != logical_id:
                graph.add_edge(logical_id, target)

    return graph


def _referenced_logical_ids(resource, resources):
    found = set()

    for depends_on in _as_list(resource.get("DependsOn")):
        if depends_on in resources:
            found.add(depends_on)

    _walk(resource.get("Properties", {}), resources, found)
    return found


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _walk(node, resources, found):
    if isinstance(node, dict):
        if len(node) == 1 and "Ref" in node:
            target = node["Ref"]
            if target in resources:
                found.add(target)
            return

        if len(node) == 1 and "Fn::GetAtt" in node:
            target = node["Fn::GetAtt"]
            target = target[0] if isinstance(target, list) else target.split(".", 1)[0]
            if target in resources:
                found.add(target)
            return

        if len(node) == 1 and "Fn::Sub" in node:
            sub_value = node["Fn::Sub"]
            sub_string = sub_value[0] if isinstance(sub_value, list) else sub_value
            for token in _SUB_TOKEN_RE.findall(sub_string):
                target = token.split(".", 1)[0]
                if target in resources:
                    found.add(target)
            if isinstance(sub_value, list):
                _walk(sub_value[1], resources, found)
            return

        for value in node.values():
            _walk(value, resources, found)

    elif isinstance(node, list):
        for item in node:
            _walk(item, resources, found)
