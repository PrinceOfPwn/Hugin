#!/usr/bin/env python3
"""Validate the generated HUGIN v2 static site using only the Python stdlib."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from collections import Counter, deque
from pathlib import Path
from typing import Any


EXPECTED_NODES = 379
EXPECTED_RAW_EDGES = 376
EXPECTED_EMBEDDED_EDGES = 584
EXPECTED_CONTENTS = 379
EXPECTED_INFERRED_EDGES = 208
EXPECTED_CURATED_EDGES = EXPECTED_EMBEDDED_EDGES - EXPECTED_INFERRED_EDGES

EMBEDDED_SCRIPT_ID = "hugin-graph-data"
REQUIRED_RAVEN_ASSETS = (
    "assets/raven-source.jpg",
    "assets/raven-source.png",
    "assets/raven-mark.png",
    "assets/raven-red.png",
    "assets/raven-black.png",
    "assets/favicon.png",
)
WEB_REFERENCED_RAVEN_ASSETS = (
    "assets/raven-mark.png",
    "assets/raven-red.png",
    "assets/raven-black.png",
    "assets/favicon.png",
)
RAVEN_SHA256 = {
    "assets/raven-source.jpg": "2f19538b67699d41b1b683841dc29d43aa69e2c4f60b050af48bc0d3426a7a2a",
    "assets/raven-source.png": "06f87fb96daa970ac023f3515464237722f20b0f8782767d134042e994451061",
    "assets/raven-mark.png": "ff2b510d8bedfbc682b6d4507279383fde54af5cb343a9b6d9f90522cc406223",
    "assets/raven-red.png": "3fa5e2628d9881d711376dbe2015190ca786e7e4b4267527ce16fb61844ba999",
    "assets/raven-black.png": "04052cd2d7aaa73ebb3be9f91c7ddbeaa61090e630ddc93753ec279aa11b06c0",
    "assets/favicon.png": "92a78a92cb9b4a667d91ea2f8a0f02e3da530d35013256686c3ae0f33d3b7ee5",
}
RAVEN_SOURCE_URL_FRAGMENT = "vectorstock.com/i/500p/12/14/raven-opened-its-wings-and-trampled-paws-vector-40631214.jpg"
RECYCLED_ID = "src:dark_crystal/crowd/src/recycled.rs"
TECHNIQUE_ID = "T-001"

SCRIPT_OPEN_RE = re.compile(
    rf"<script\b(?=[^>]*\bid\s*=\s*(['\"]){re.escape(EMBEDDED_SCRIPT_ID)}\1)[^>]*>",
    re.IGNORECASE,
)
SCRIPT_CLOSE_RE = re.compile(r"</script\s*>", re.IGNORECASE)
ID_RE = re.compile(r"\bid\s*=\s*(['\"])([^'\"]+)\1", re.IGNORECASE)


class Validation:
    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose
        self.passed = 0
        self.failed = 0

    def check(self, condition: bool, label: str, detail: str = "") -> bool:
        if condition:
            self.passed += 1
            if self.verbose:
                print(f"PASS  {label}{': ' + detail if detail else ''}")
            return True
        self.failed += 1
        print(f"FAIL  {label}{': ' + detail if detail else ''}", file=sys.stderr)
        return False

    def note(self, message: str) -> None:
        print(f"INFO  {message}")

    def finish(self) -> int:
        status = "OK" if self.failed == 0 else "FAILED"
        print(f"\n{status}: {self.passed} checks passed, {self.failed} failed")
        return 0 if self.failed == 0 else 1


def parse_args() -> argparse.Namespace:
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Validate HUGIN's generated HTML, embedded graph, assets, and source graph."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=project_root,
        help=f"project root (default: {project_root})",
    )
    parser.add_argument(
        "--source-template",
        nargs="?",
        const="hugin/index.template.html",
        metavar="PATH",
        help="also validate the source template and its graph-data marker",
    )
    parser.add_argument("--verbose", action="store_true", help="print successful checks")
    return parser.parse_args()


def resolve_under_root(root: Path, value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else root / path


def read_text(path: Path, validation: Validation, label: str) -> str | None:
    if not validation.check(path.is_file(), label, str(path)):
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        validation.check(False, f"{label} is readable UTF-8", str(exc))
        return None


def load_json(path: Path, validation: Validation, label: str) -> dict[str, Any] | None:
    text = read_text(path, validation, f"{label} exists")
    if text is None:
        return None
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        validation.check(False, f"{label} parses as JSON", f"line {exc.lineno}, column {exc.colno}: {exc.msg}")
        return None
    if not validation.check(isinstance(value, dict), f"{label} root is an object"):
        return None
    validation.check(True, f"{label} parses as JSON")
    return value


def extract_embedded_graph(
    html: str, validation: Validation
) -> tuple[dict[str, Any] | None, str, str]:
    """Return (parsed graph, raw payload, HTML without the payload script)."""
    openings = list(SCRIPT_OPEN_RE.finditer(html))
    if not validation.check(
        len(openings) == 1,
        f"exactly one #{EMBEDDED_SCRIPT_ID} script exists",
        f"found {len(openings)}",
    ):
        return None, "", html

    opening = openings[0]
    opening_tag = opening.group(0)
    validation.check(
        bool(re.search(r"\btype\s*=\s*(['\"])application/json\1", opening_tag, re.IGNORECASE)),
        f"#{EMBEDDED_SCRIPT_ID} uses type=application/json",
    )

    closings = list(SCRIPT_CLOSE_RE.finditer(html, opening.end()))
    if not validation.check(bool(closings), f"#{EMBEDDED_SCRIPT_ID} has a closing tag"):
        return None, "", html

    first_error: json.JSONDecodeError | None = None
    for index, closing in enumerate(closings):
        payload = html[opening.end() : closing.start()]
        try:
            value = json.loads(payload)
        except json.JSONDecodeError as exc:
            if first_error is None:
                first_error = exc
            continue

        validation.check(
            index == 0,
            "embedded payload contains no unsafe literal </script>",
            "an earlier </script> terminates the browser script before the valid JSON endpoint"
            if index
            else "",
        )
        validation.check(
            re.search(r"</script", payload, re.IGNORECASE) is None,
            "embedded payload has no case-insensitive </script sequence",
        )
        shell_html = html[: opening.start()] + html[closing.end() :]
        if not validation.check(isinstance(value, dict), "embedded graph root is an object"):
            return None, payload, shell_html
        validation.check(True, "embedded graph parses as JSON")
        return value, payload, shell_html

    detail = "no closing-tag candidate completes valid JSON"
    if first_error is not None:
        detail = f"line {first_error.lineno}, column {first_error.colno}: {first_error.msg}"
    validation.check(False, "embedded graph parses as JSON", detail)
    first_closing = closings[0]
    shell_html = html[: opening.start()] + html[first_closing.end() :]
    return None, html[opening.end() : first_closing.start()], shell_html


def graph_collections(
    graph: dict[str, Any], validation: Validation, label: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, str]] | None:
    nodes = graph.get("nodes")
    edges = graph.get("edges")
    contents = graph.get("contents")
    ok = True
    ok &= validation.check(isinstance(nodes, list), f"{label}.nodes is an array")
    ok &= validation.check(isinstance(edges, list), f"{label}.edges is an array")
    ok &= validation.check(isinstance(contents, dict), f"{label}.contents is an object")
    if not ok:
        return None
    if not all(isinstance(node, dict) for node in nodes):
        validation.check(False, f"{label}.nodes contains only objects")
        return None
    validation.check(True, f"{label}.nodes contains only objects")
    if not all(isinstance(edge, dict) for edge in edges):
        validation.check(False, f"{label}.edges contains only objects")
        return None
    validation.check(True, f"{label}.edges contains only objects")
    if not all(isinstance(key, str) and isinstance(value, str) for key, value in contents.items()):
        validation.check(False, f"{label}.contents maps string IDs to full text")
        return None
    validation.check(True, f"{label}.contents maps string IDs to full text")
    return nodes, edges, contents


def validate_counts(
    validation: Validation,
    label: str,
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    contents: dict[str, str],
    edge_count: int,
) -> None:
    validation.check(len(nodes) == EXPECTED_NODES, f"{label} has {EXPECTED_NODES} nodes", f"found {len(nodes)}")
    validation.check(len(edges) == edge_count, f"{label} has {edge_count} edges", f"found {len(edges)}")
    validation.check(
        len(contents) == EXPECTED_CONTENTS,
        f"{label} has {EXPECTED_CONTENTS} contents",
        f"found {len(contents)}",
    )


def validate_ids_and_endpoints(
    validation: Validation,
    label: str,
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> set[str] | None:
    node_ids = [node.get("id") for node in nodes]
    if not validation.check(
        all(isinstance(node_id, str) and node_id for node_id in node_ids),
        f"{label} node IDs are non-empty strings",
    ):
        return None
    ids = set(node_ids)
    validation.check(len(ids) == len(node_ids), f"{label} node IDs are unique")

    malformed = [
        index
        for index, edge in enumerate(edges)
        if not isinstance(edge.get("source"), str)
        or not isinstance(edge.get("target"), str)
        or not isinstance(edge.get("type"), str)
    ]
    validation.check(
        not malformed,
        f"{label} edges have source, target, and type strings",
        f"bad indexes: {malformed[:8]}" if malformed else "",
    )
    invalid = [
        (index, edge.get("source"), edge.get("target"))
        for index, edge in enumerate(edges)
        if edge.get("source") not in ids or edge.get("target") not in ids
    ]
    validation.check(
        not invalid,
        f"{label} edge endpoints all exist",
        f"bad edges: {invalid[:5]}" if invalid else "",
    )
    return ids


def validate_edge_provenance(validation: Validation, edges: list[dict[str, Any]]) -> None:
    inferred = [edge for edge in edges if edge.get("inferred") is True]
    curated = [edge for edge in edges if edge.get("inferred") is not True]
    validation.check(
        len(curated) == EXPECTED_CURATED_EDGES,
        f"embedded graph has {EXPECTED_CURATED_EDGES} curated edges",
        f"found {len(curated)}",
    )
    validation.check(
        len(inferred) == EXPECTED_INFERRED_EDGES,
        f"embedded graph has {EXPECTED_INFERRED_EDGES} inferred edges",
        f"found {len(inferred)}",
    )

    missing_metadata: list[int] = []
    for index, edge in enumerate(edges):
        if edge.get("inferred") is not True:
            continue
        if any(edge.get(key) in (None, "", [], {}) for key in ("confidence", "reason", "provenance")):
            missing_metadata.append(index)
    validation.check(
        not missing_metadata,
        "every inferred edge has confidence, reason, and provenance",
        f"bad indexes: {missing_metadata[:8]}" if missing_metadata else "",
    )


def validate_connectivity(
    validation: Validation,
    node_ids: set[str],
    edges: list[dict[str, Any]],
) -> None:
    adjacency: dict[str, set[str]] = {node_id: set() for node_id in node_ids}
    for edge in edges:
        source = edge.get("source")
        target = edge.get("target")
        if source in adjacency and target in adjacency:
            adjacency[source].add(target)
            adjacency[target].add(source)

    isolates = sorted(node_id for node_id, neighbors in adjacency.items() if not neighbors)
    validation.check(
        not isolates,
        "embedded graph has no isolated nodes",
        f"isolates: {isolates[:8]}" if isolates else "",
    )

    components: list[set[str]] = []
    unseen = set(node_ids)
    while unseen:
        start = next(iter(unseen))
        component = {start}
        queue = deque([start])
        unseen.remove(start)
        while queue:
            current = queue.popleft()
            for neighbor in adjacency[current]:
                if neighbor in unseen:
                    unseen.remove(neighbor)
                    component.add(neighbor)
                    queue.append(neighbor)
        components.append(component)
    sizes = sorted((len(component) for component in components), reverse=True)
    validation.check(
        len(components) == 1,
        "embedded graph is one undirected connected component",
        f"component sizes: {sizes}" if len(components) != 1 else "",
    )


def validate_full_contents(
    validation: Validation,
    embedded_contents: dict[str, str],
    raw_contents: dict[str, str],
) -> None:
    for node_id, friendly_name, minimum_size in (
        (RECYCLED_ID, "full recycled.rs", 20_000),
        (TECHNIQUE_ID, "full T-001 technique", 30_000),
    ):
        embedded = embedded_contents.get(node_id)
        raw = raw_contents.get(node_id)
        validation.check(isinstance(embedded, str), f"embedded contents include {node_id}")
        if not isinstance(embedded, str):
            continue
        validation.check(
            len(embedded) >= minimum_size,
            f"embedded contents retain {friendly_name}",
            f"length {len(embedded)}",
        )
        validation.check(
            isinstance(raw, str) and embedded == raw,
            f"embedded {node_id} exactly matches graph.json",
            f"embedded length {len(embedded)}, raw length {len(raw) if isinstance(raw, str) else 'missing'}",
        )


def validate_embedded_preserves_source(
    validation: Validation,
    embedded: tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, str]],
    raw: tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, str]],
) -> None:
    embedded_nodes, embedded_edges, embedded_contents = embedded
    raw_nodes, raw_edges, raw_contents = raw
    embedded_ids = {
        node_id for node in embedded_nodes if isinstance((node_id := node.get("id")), str)
    }
    raw_ids = {node_id for node in raw_nodes if isinstance((node_id := node.get("id")), str)}
    validation.check(
        embedded_ids == raw_ids,
        "embedded graph preserves the raw node ID set",
        f"missing {sorted(raw_ids - embedded_ids)[:5]}, extra {sorted(embedded_ids - raw_ids)[:5]}",
    )
    validation.check(
        set(embedded_contents) == embedded_ids,
        "embedded contents have exactly one entry per node",
    )
    validation.check(
        embedded_contents == raw_contents,
        "embedded graph preserves all raw content text exactly",
    )

    def signature(edge: dict[str, Any]) -> tuple[Any, Any, Any]:
        return edge.get("source"), edge.get("target"), edge.get("type")

    curated_signatures = Counter(
        signature(edge) for edge in embedded_edges if edge.get("inferred") is not True
    )
    raw_signatures = Counter(signature(edge) for edge in raw_edges)
    validation.check(
        curated_signatures == raw_signatures,
        "embedded curated edges exactly preserve graph.json",
    )


def validate_forbidden_runtime(validation: Validation, shell_html: str) -> None:
    forbidden = (
        (r"fetch\s*\(\s*(['\"])[^'\"]*graph\.json[^'\"]*\1", "no fetch('graph.json') runtime dependency"),
        (r"\bFileReader\b", "no FileReader fallback"),
        (r"\bid\s*=\s*(['\"])local-gate\1", "no local file gate"),
        (r"LOCAL\s+VAULT\s+ACCESS", "no LOCAL VAULT ACCESS copy"),
        (r"<input\b[^>]*\btype\s*=\s*(['\"])file\1", "no file input"),
        (r"\bid\s*=\s*(['\"])(?:choose-graph|graph-file)\1", "no graph chooser controls"),
    )
    for pattern, label in forbidden:
        validation.check(re.search(pattern, shell_html, re.IGNORECASE) is None, label)


def validate_required_controls(validation: Validation, shell_html: str) -> None:
    ids = {match.group(2) for match in ID_RE.finditer(shell_html)}
    required_exact = {
        "graph canvas": ("graph-view", "cy"),
        "trace status": ("trace-status",),
        "inferred edge toggle": ("inferred-toggle",),
        "Raven Flight viewport": ("flight-view", "flight-stage"),
        "Raven Flight entry and exit": ("flight-btn", "flight-exit"),
    }
    for feature, required_ids in required_exact.items():
        missing = [required_id for required_id in required_ids if required_id not in ids]
        validation.check(
            not missing,
            f"UI exposes {feature}",
            f"missing IDs: {', '.join(missing)}" if missing else "",
        )

    aliases = {"relationship deck": ("relation-deck", "relationship-deck", "details-neighbors")}
    for feature, candidates in aliases.items():
        matches = sorted(set(candidates) & ids)
        validation.check(
            bool(matches),
            f"UI exposes {feature}",
            f"expected one of: {', '.join(candidates)}" if not matches else f"using {', '.join(matches)}",
        )
    validation.check("flight-relations" in ids, "UI exposes Raven Flight relationship selector", "missing ID: flight-relations" if "flight-relations" not in ids else "using flight-relations")

    behavior_markers = (
        ("const flightNodes=state.cy.nodes()", "Raven Flight constructs the complete vault"),
        ("state.cy.edges().forEach(edge=>", "Raven Flight constructs all relationships"),
        ("current.connectedEdges().map(edge=>", "Raven Flight relation deck includes hidden 2D relations"),
        ("buildFlightChevrons(routeBuckets)", "Raven Flight renders directional chevrons"),
        ("['technique','source','source-extract','documentation','architecture']", "CODE MAP includes its documentation column"),
        ("traceStepLabel", "trace reports level, direction, and relationship type"),
    )
    for marker, label in behavior_markers:
        validation.check(marker in shell_html, label)


def png_info(path: Path) -> tuple[int, int, bool] | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) < 33 or data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        return None
    width, height = struct.unpack(">II", data[16:24])
    color_type = data[25]
    has_alpha = color_type in (4, 6) or b"tRNS" in data
    return width, height, has_alpha


def validate_raven_assets(validation: Validation, root: Path, shell_html: str) -> None:
    for relative in REQUIRED_RAVEN_ASSETS:
        path = root / "hugin" / relative
        exists = validation.check(path.is_file(), f"raven asset exists: {relative}")
        if not exists:
            continue
        try:
            size = path.stat().st_size
        except OSError as exc:
            validation.check(False, f"raven asset is readable: {relative}", str(exc))
            continue
        validation.check(size > 100, f"raven asset is non-empty: {relative}", f"{size} bytes")
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            digest = ""
        validation.check(digest == RAVEN_SHA256[relative], f"raven asset matches the approved exact derivative: {relative}")
        if relative.endswith(".jpg"):
            try:
                signature = path.read_bytes()[:2]
            except OSError:
                signature = b""
            validation.check(signature == b"\xff\xd8", f"raven source is a JPEG: {relative}")
        elif relative.endswith(".png"):
            info = png_info(path)
            validation.check(info is not None, f"raven asset is a valid PNG: {relative}")
            if info is not None:
                width, height, has_alpha = info
                validation.check(width >= 32 and height >= 32, f"raven PNG has usable dimensions: {relative}", f"{width}x{height}")
                if relative in {"assets/raven-mark.png", "assets/raven-red.png", "assets/raven-black.png"}:
                    validation.check(has_alpha, f"processed raven PNG has transparency: {relative}")

    normalized_html = shell_html.replace("\\/", "/")
    for relative in WEB_REFERENCED_RAVEN_ASSETS:
        validation.check(relative in normalized_html, f"HTML references {relative}")

    inline_raven = re.search(
        r"<svg\b[^>]*(?:class|id)\s*=\s*(['\"])[^'\"]*raven[^'\"]*\1",
        shell_html,
        re.IGNORECASE,
    )
    validation.check(inline_raven is None, "HTML contains no replacement inline raven drawing")

    readme = root / "hugin" / "README.md"
    source_note = root / "hugin" / "assets" / "SOURCE.md"
    attribution_text = shell_html
    for document in (readme, source_note):
        if not document.is_file():
            continue
        try:
            attribution_text += "\n" + document.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            pass
    validation.check(
        RAVEN_SOURCE_URL_FRAGMENT in attribution_text,
        "raven source URL is documented",
    )


def validate_source_template(
    validation: Validation,
    root: Path,
    template_arg: str,
    generated_html: str,
) -> None:
    template_path = resolve_under_root(root, template_arg)
    template = read_text(template_path, validation, "source template exists")
    if template is None:
        return

    markers = (
        "<!-- HUGIN_GRAPH_DATA -->",
        "__HUGIN_GRAPH_DATA__",
        "{{HUGIN_GRAPH_DATA}}",
        "{{ HUGIN_GRAPH_DATA }}",
    )
    counts = {marker: template.count(marker) for marker in markers}
    present = [(marker, count) for marker, count in counts.items() if count]
    validation.check(
        sum(count for _, count in present) == 1,
        "source template has exactly one graph-data marker",
        f"found {present}" if present else f"expected one of: {', '.join(markers)}",
    )
    validation.check(
        not any(marker in generated_html for marker in markers),
        "generated index contains no unresolved graph-data marker",
    )

    opening = SCRIPT_OPEN_RE.search(template)
    if opening:
        closing = SCRIPT_CLOSE_RE.search(template, opening.end())
        payload = template[opening.end() : closing.start()] if closing else ""
        validation.check(closing is not None, "source template graph-data script has a closing tag")
        validation.check(
            len(payload.strip()) < 1_000,
            "source template does not duplicate the full embedded graph",
            f"payload length {len(payload)}",
        )
    else:
        validation.check(True, "source template keeps graph payload external to its static markup")


def main() -> int:
    args = parse_args()
    root = args.root.expanduser().resolve()
    validation = Validation(verbose=args.verbose)
    validation.note(f"project root: {root}")

    index_path = root / "hugin" / "index.html"
    html = read_text(index_path, validation, "hugin/index.html exists")
    if html is None:
        return validation.finish()

    embedded_graph, _payload, shell_html = extract_embedded_graph(html, validation)
    raw_graph = load_json(root / "hugin" / "graph.json", validation, "raw graph.json")

    raw_collections = None
    if raw_graph is not None:
        raw_collections = graph_collections(raw_graph, validation, "raw graph")
        if raw_collections is not None:
            raw_nodes, raw_edges, raw_contents = raw_collections
            validate_counts(
                validation,
                "raw graph",
                raw_nodes,
                raw_edges,
                raw_contents,
                EXPECTED_RAW_EDGES,
            )
            validate_ids_and_endpoints(validation, "raw graph", raw_nodes, raw_edges)

    embedded_collections = None
    if embedded_graph is not None:
        embedded_collections = graph_collections(embedded_graph, validation, "embedded graph")
        if embedded_collections is not None:
            embedded_nodes, embedded_edges, embedded_contents = embedded_collections
            validate_counts(
                validation,
                "embedded graph",
                embedded_nodes,
                embedded_edges,
                embedded_contents,
                EXPECTED_EMBEDDED_EDGES,
            )
            embedded_ids = validate_ids_and_endpoints(
                validation, "embedded graph", embedded_nodes, embedded_edges
            )
            validate_edge_provenance(validation, embedded_edges)
            if embedded_ids is not None:
                validate_connectivity(validation, embedded_ids, embedded_edges)
            if raw_collections is not None:
                validate_full_contents(validation, embedded_contents, raw_collections[2])
                validate_embedded_preserves_source(validation, embedded_collections, raw_collections)

    validate_forbidden_runtime(validation, shell_html)
    validate_required_controls(validation, shell_html)
    validate_raven_assets(validation, root, shell_html)

    if args.source_template is not None:
        validate_source_template(validation, root, args.source_template, html)

    return validation.finish()


if __name__ == "__main__":
    raise SystemExit(main())
