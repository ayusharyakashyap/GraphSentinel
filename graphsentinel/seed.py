"""Validate and idempotently load the checked-in synthetic graph fixture."""

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from falkordb import FalkorDB

from graphsentinel.config import settings
from graphsentinel.schema import NODE_REQUIRED_PROPERTIES, RELATIONSHIP_ENDPOINTS

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "data" / "demo_graph.json"


def load_fixture(path: Path = FIXTURE_PATH) -> dict[str, Any]:
    with path.open(encoding="utf-8") as fixture_file:
        fixture = json.load(fixture_file)
    validate_fixture(fixture)
    return fixture


def validate_fixture(fixture: dict[str, Any]) -> None:
    nodes = fixture.get("nodes", [])
    edges = fixture.get("relationships", [])
    node_by_id: dict[str, dict[str, Any]] = {}
    for node in nodes:
        label = node.get("label")
        properties = node.get("properties", {})
        identifier = node.get("id")
        if label not in NODE_REQUIRED_PROPERTIES or not identifier:
            raise ValueError(f"Unknown node label or missing node ID: {node!r}")
        if identifier in node_by_id:
            raise ValueError(f"Duplicate node ID: {identifier}")
        missing = NODE_REQUIRED_PROPERTIES[label] - properties.keys()
        if missing or properties.get("id") != identifier:
            raise ValueError(f"Invalid {label} {identifier}: missing {sorted(missing)} or mismatched id")
        node_by_id[identifier] = node

    for edge in edges:
        edge_type = edge.get("type")
        source = node_by_id.get(edge.get("from_id"))
        target = node_by_id.get(edge.get("to_id"))
        endpoints = (source["label"], target["label"]) if source and target else None
        if endpoints not in RELATIONSHIP_ENDPOINTS.get(edge_type, set()):
            raise ValueError(f"Invalid relationship or endpoint: {edge!r}")


def connect_graph():
    client = FalkorDB(
        host=settings.host,
        port=settings.port,
        password=settings.password,
    )
    return client.select_graph(settings.graph_name)


def seed_graph(graph: Any, fixture: dict[str, Any]) -> dict[str, int]:
    validate_fixture(fixture)
    nodes_by_label: dict[str, list[dict[str, Any]]] = {}
    for node in fixture["nodes"]:
        nodes_by_label.setdefault(node["label"], []).append(node)

    for label, rows in nodes_by_label.items():
        graph.query(
            f"UNWIND $rows AS row MERGE (n:{label} {{id: row.id}}) "
            "SET n += row.properties",
            {"rows": rows},
        )

    edges_by_type: dict[str, list[dict[str, Any]]] = {}
    for edge in fixture["relationships"]:
        edges_by_type.setdefault(edge["type"], []).append(edge)

    for edge_type, rows in edges_by_type.items():
        graph.query(
            "UNWIND $rows AS row "
            "MATCH (source {id: row.from_id}) "
            "MATCH (target {id: row.to_id}) "
            f"MERGE (source)-[r:{edge_type}]->(target) "
            "SET r += row.properties",
            {"rows": rows},
        )

    node_count = graph.query("MATCH (n) RETURN count(n)").result_set[0][0]
    relationship_count = graph.query(
        "MATCH ()-[r]->() RETURN count(r)"
    ).result_set[0][0]
    return {"nodes": node_count, "relationships": relationship_count}


def reset_demo_graph() -> None:
    if settings.graph_name != "graphsentinel":
        raise ValueError("Demo reset is restricted to the graph named 'graphsentinel'.")
    connect_graph().delete()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reset-demo",
        action="store_true",
        help="Delete and recreate only the graph named graphsentinel.",
    )
    args = parser.parse_args()
    fixture = load_fixture()
    if args.reset_demo:
        reset_demo_graph()
    counts = seed_graph(connect_graph(), fixture)
    labels = Counter(node["label"] for node in fixture["nodes"])
    print(
        f"Loaded {settings.graph_name}: {counts['nodes']} nodes, "
        f"{counts['relationships']} relationships; fixture labels: {dict(labels)}"
    )


if __name__ == "__main__":
    main()