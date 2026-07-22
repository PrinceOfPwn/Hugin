#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from collections import Counter, deque
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_TYPES = {
    "technique": 23,
    "playbook": 36,
    "source-extract": 10,
    "reference": 1,
    "source": 157,
    "documentation": 149,
    "pattern": 1,
    "architecture": 2,
}
CONFIDENCE_SCORES = {
    "exact-file": 1.0,
    "exact-id": 1.0,
    "exact-structure": 0.98,
    "explicit-id": 0.95,
    "structural-role": 0.72,
    "fallback": 0.4,
}
REQUIRED_ASSETS = (
    "raven-mark.png",
    "raven-red.png",
    "raven-black.png",
    "favicon.png",
)


class BuildError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise BuildError(message)


def load_graph(path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BuildError(f"Cannot read {path}: {error}") from error

    require(isinstance(data, dict), "graph.json must contain an object")
    nodes = data.get("nodes")
    edges = data.get("edges")
    contents = data.get("contents")
    require(isinstance(nodes, list), "nodes must be an array")
    require(isinstance(edges, list), "edges must be an array")
    require(isinstance(contents, dict), "contents must be an object")
    require(len(nodes) == 379, f"Expected 379 nodes, found {len(nodes)}")
    require(len(edges) == 376, f"Expected 376 curated edges, found {len(edges)}")
    require(len(contents) == 379, f"Expected 379 contents, found {len(contents)}")

    ids = [node.get("id") for node in nodes]
    require(all(isinstance(node_id, str) and node_id for node_id in ids), "Every node needs a non-empty string id")
    require(len(ids) == len(set(ids)), "Node ids must be unique")
    id_set = set(ids)
    require(set(contents) == id_set, "contents keys must match node ids exactly")
    require(Counter(node.get("type") for node in nodes) == Counter(EXPECTED_TYPES), "Node type counts do not match the HUGIN manifest")

    edge_keys = []
    for index, edge in enumerate(edges):
        source = edge.get("source")
        target = edge.get("target")
        edge_type = edge.get("type")
        require(source in id_set, f"Curated edge {index} has unknown source {source!r}")
        require(target in id_set, f"Curated edge {index} has unknown target {target!r}")
        require(edge_type in {"requires", "enables", "reference", "implements"}, f"Curated edge {index} has invalid type {edge_type!r}")
        edge_keys.append((source, target, edge_type))
    require(len(edge_keys) == len(set(edge_keys)), "Curated edges contain duplicate source/target/type tuples")
    return data


def enrich_graph(data):
    nodes = data["nodes"]
    contents = data["contents"]
    by_id = {node["id"]: node for node in nodes}
    by_file = {node["file"]: node for node in nodes if node.get("file")}
    edges = []
    keys = set()
    curated_degree = Counter()

    for edge in data["edges"]:
        enriched = dict(edge)
        enriched.update(
            inferred=False,
            confidence="curated",
            confidence_score=1.0,
            reason="Curated vault relationship",
            provenance={"method": "curated-graph", "source": "graph.json"},
        )
        edges.append(enriched)
        keys.add((edge["source"], edge["target"], edge["type"]))
        curated_degree[edge["source"]] += 1
        curated_degree[edge["target"]] += 1

    def add(source, target, edge_type, reason, confidence, provenance):
        key = (source, target, edge_type)
        if source not in by_id or target not in by_id or source == target or key in keys:
            return False
        keys.add(key)
        edges.append(
            {
                "source": source,
                "target": target,
                "type": edge_type,
                "inferred": True,
                "confidence": confidence,
                "confidence_score": CONFIDENCE_SCORES[confidence],
                "reason": reason,
                "provenance": provenance,
            }
        )
        return True

    technique_pattern = re.compile(r"\bT-?(\d{3})\b", re.IGNORECASE)

    def technique_ids(raw):
        found = []
        seen = set()
        for match in technique_pattern.finditer(str(raw or "")):
            technique_id = f"T-{match.group(1)}"
            if technique_id in seen or by_id.get(technique_id, {}).get("type") != "technique":
                continue
            seen.add(technique_id)
            found.append(technique_id)
        return found

    source_field = re.compile(r"\*\*Source\*\*\s*\|\s*`([^`]+)`", re.IGNORECASE)
    for node in (item for item in nodes if item.get("type") == "documentation"):
        match = source_field.search(contents.get(node["id"], ""))
        source = by_file.get(match.group(1)) if match else None
        if source:
            add(
                node["id"],
                source["id"],
                "semantic",
                f"Generated documentation for {match.group(1)}",
                "exact-file",
                {"method": "documentation-source-field", "evidence": match.group(1)},
            )

    for node in (item for item in nodes if item.get("type") == "source-extract"):
        for technique_id in technique_ids(contents.get(node["id"], "")[:5000])[:2]:
            add(
                node["id"],
                technique_id,
                "implements",
                f"Source extract explicitly names {technique_id}",
                "explicit-id",
                {"method": "content-technique-id", "evidence": technique_id, "scope": "first-5000-characters"},
            )

    playbook_pattern = re.compile(r"playbook:T(\d{3})", re.IGNORECASE)
    for node in (item for item in nodes if item.get("type") == "playbook"):
        match = playbook_pattern.search(node["id"])
        technique_id = f"T-{match.group(1)}" if match else None
        if technique_id:
            add(
                node["id"],
                technique_id,
                "reference",
                f"Playbook identifier maps directly to {technique_id}",
                "exact-id",
                {"method": "playbook-id", "evidence": node["id"]},
            )

    for node in (item for item in nodes if item.get("type") in {"architecture", "reference", "pattern"}):
        limit = 23 if node["type"] == "reference" else 10 if node["type"] == "architecture" else 5
        for technique_id in technique_ids(contents.get(node["id"], ""))[:limit]:
            add(
                node["id"],
                technique_id,
                "semantic",
                f"{node['label']} explicitly discusses {technique_id}",
                "explicit-id",
                {"method": "content-technique-id", "evidence": technique_id},
            )

    dependency_anchor = "architecture:dependency-map" if "architecture:dependency-map" in by_id else "T-001"
    overview_anchor = "architecture:overview" if "architecture:overview" in by_id else dependency_anchor
    for node in (item for item in nodes if item.get("type") == "source" and not curated_degree[item["id"]]):
        evidence = node.get("role") or node.get("file") or node.get("label")
        text = f"{node.get('file', '')} {node.get('role', '')}".lower()
        target = dependency_anchor
        if "client_rust" in text:
            target = "T-023"
        elif "transport" in text or "payload acquisition" in text:
            target = "T-019"
        elif "nt api" in text:
            target = "T-001"
        elif "crowd/src" in text or "runner" in text or "framework/runtime" in text:
            target = overview_anchor
        add(
            node["id"],
            target,
            "semantic",
            f"Support/runtime code: {evidence}",
            "structural-role",
            {"method": "source-role-anchor", "evidence": evidence, "anchor": target},
        )

    if "pattern:rust-patterns" in by_id:
        add(
            "pattern:rust-patterns",
            overview_anchor,
            "semantic",
            "Rust patterns are used across the runtime architecture",
            "structural-role",
            {"method": "vault-structure", "evidence": "patterns-to-architecture"},
        )
    if "architecture:dependency-map" in by_id and "architecture:overview" in by_id:
        add(
            "architecture:dependency-map",
            "architecture:overview",
            "semantic",
            "Dependency map expands the system overview",
            "exact-structure",
            {"method": "vault-structure", "evidence": "dependency-map-to-overview"},
        )
    if "architecture:overview" in by_id:
        add(
            "architecture:overview",
            "T-001",
            "semantic",
            "System architecture anchors the technique execution layer",
            "structural-role",
            {"method": "architecture-anchor", "evidence": "T-001"},
        )
    if "architecture:dependency-map" in by_id:
        add(
            "architecture:dependency-map",
            "T-023",
            "semantic",
            "Dependency map spans the client and runtime layers",
            "structural-role",
            {"method": "architecture-anchor", "evidence": "T-023"},
        )

    degree = Counter()
    for edge in edges:
        degree[edge["source"]] += 1
        degree[edge["target"]] += 1
    for node in (item for item in nodes if not degree[item["id"]]):
        add(
            node["id"],
            dependency_anchor,
            "semantic",
            f"Vault placement inferred from {node.get('type')} metadata",
            "fallback",
            {"method": "isolate-fallback", "evidence": node.get("type"), "anchor": dependency_anchor},
        )

    result = dict(data)
    result["edges"] = edges
    result["edge_types"] = dict(data.get("edge_types", {}))
    result["edge_types"]["semantic"] = {
        "label": "Semantic links",
        "style": "dotted",
        "color": "#9b30ff",
        "inferred": True,
    }
    result["build_meta"] = {
        "schema_version": 2,
        "curated_edges": len(data["edges"]),
        "inferred_edges": len(edges) - len(data["edges"]),
        "total_edges": len(edges),
    }
    validate_enriched(result)
    return result


def validate_enriched(data):
    nodes = data["nodes"]
    edges = data["edges"]
    ids = {node["id"] for node in nodes}
    inferred = [edge for edge in edges if edge.get("inferred")]
    require(len(edges) == 584, f"Expected 584 enriched edges, found {len(edges)}")
    require(len(inferred) == 208, f"Expected 208 inferred edges, found {len(inferred)}")
    require(all(edge.get("reason") and edge.get("confidence") and edge.get("provenance") for edge in inferred), "Every inferred edge needs reason, confidence and provenance")

    degree = Counter()
    adjacency = {node_id: set() for node_id in ids}
    edge_keys = set()
    for index, edge in enumerate(edges):
        source = edge.get("source")
        target = edge.get("target")
        edge_type = edge.get("type")
        require(source in ids, f"Enriched edge {index} has unknown source {source!r}")
        require(target in ids, f"Enriched edge {index} has unknown target {target!r}")
        key = (source, target, edge_type)
        require(key not in edge_keys, f"Duplicate enriched edge {key}")
        edge_keys.add(key)
        degree[source] += 1
        degree[target] += 1
        adjacency[source].add(target)
        adjacency[target].add(source)
    isolates = sorted(node_id for node_id in ids if not degree[node_id])
    require(not isolates, f"Isolated nodes remain: {', '.join(isolates)}")

    start = next(iter(ids))
    visited = {start}
    queue = deque([start])
    while queue:
        current = queue.popleft()
        for neighbor in adjacency[current]:
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)
    if len(visited) != len(ids):
        raise BuildError(f"Enriched graph is disconnected: reached {len(visited)} of {len(ids)} nodes")


def serialize_for_html(data):
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return payload.replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def render(template_path, data):
    try:
        template = template_path.read_text(encoding="utf-8")
    except OSError as error:
        raise BuildError(f"Cannot read {template_path}: {error}") from error
    marker = "__HUGIN_GRAPH_DATA__"
    require(template.count(marker) == 1, f"{template_path} must contain exactly one {marker} marker")
    return template.replace(marker, serialize_for_html(data))


def atomic_write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        handle.write(text)
        temporary = Path(handle.name)
    os.replace(temporary, path)


def verify_assets(assets_dir):
    missing = [name for name in REQUIRED_ASSETS if not (assets_dir / name).is_file()]
    require(not missing, f"Missing runtime assets: {', '.join(missing)}")


def write_dist(dist, rendered, assets_dir):
    dist.mkdir(parents=True, exist_ok=True)
    atomic_write(dist / "index.html", rendered)
    shutil.copytree(assets_dir, dist / "assets", dirs_exist_ok=True)
    (dist / ".nojekyll").write_text("", encoding="utf-8")


def parse_args():
    parser = argparse.ArgumentParser(description="Validate, enrich and embed the HUGIN knowledge graph")
    parser.add_argument("--graph", type=Path, default=ROOT / "hugin" / "graph.json")
    parser.add_argument("--template", type=Path, default=ROOT / "hugin" / "index.template.html")
    parser.add_argument("--output", type=Path, default=ROOT / "hugin" / "index.html")
    parser.add_argument("--dist", type=Path, help="Also stage a GitHub Pages artifact in this directory")
    parser.add_argument("--check", action="store_true", help="Validate graph, assets and generated output without writing")
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        graph = enrich_graph(load_graph(args.graph))
        assets_dir = args.template.parent / "assets"
        verify_assets(assets_dir)
        rendered = render(args.template, graph)
        digest = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
        if args.check:
            require(args.output.is_file(), f"Generated output is missing: {args.output}")
            require(args.output.read_text(encoding="utf-8") == rendered, f"Generated output is stale: run {Path(__file__).as_posix()}")
        else:
            atomic_write(args.output, rendered)
            if args.dist:
                write_dist(args.dist, rendered, assets_dir)
        print(
            f"HUGIN OK: nodes=379 curated=376 inferred=208 total=584 contents=379 "
            f"sha256={digest} mode={'check' if args.check else 'build'}"
        )
    except BuildError as error:
        print(f"HUGIN build failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
