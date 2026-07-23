import { useEffect, useMemo, useRef, useState } from "react";
import Graph from "graphology";
import Sigma from "sigma";
import type { DatasetManifest } from "../lib/types";

type Mode = "universe" | "galaxy" | "neighborhood" | "path";
type LayerName = "curated" | "membership" | "similarity";

type GraphNode = {
  id: string;
  label: string;
  kind: string;
  galaxyId: string;
  category: string;
  route: string;
  summary: string;
  scope: "core" | "support" | "structure";
  degree: number;
  x: number;
  y: number;
  size: number;
  color: string;
  isGalaxy?: boolean;
  originalLabel?: string;
};

type GraphEdge = {
  id: string;
  source: string;
  target: string;
  type: string;
  origin: LayerName;
  score?: number;
  rank?: number;
};

function initialParams() {
  return new URLSearchParams(typeof window === "undefined" ? "" : window.location.search);
}

function shortestPath(graph: Graph, start: string, goal: string) {
  const queue = [start];
  const previousNode = new Map<string, string | null>([[start, null]]);
  const previousEdge = new Map<string, string>();

  while (queue.length && !previousNode.has(goal)) {
    const current = queue.shift()!;
    for (const edge of graph.edges(current)) {
      const [source, target] = graph.extremities(edge);
      const neighbor = source === current ? target : source;
      if (previousNode.has(neighbor)) continue;
      previousNode.set(neighbor, current);
      previousEdge.set(neighbor, edge);
      queue.push(neighbor);
    }
  }

  const nodes = new Set<string>();
  const edges = new Set<string>();
  if (!previousNode.has(goal)) return { nodes, edges };
  let cursor: string | null = goal;
  while (cursor) {
    nodes.add(cursor);
    const edge = previousEdge.get(cursor);
    if (edge) edges.add(edge);
    cursor = previousNode.get(cursor) ?? null;
  }
  return { nodes, edges };
}

export default function GraphUniverse({ manifest }: { manifest: DatasetManifest }) {
  const container = useRef<HTMLDivElement>(null);
  const renderer = useRef<Sigma | null>(null);
  const graphRef = useRef<Graph | null>(null);
  const pathStart = useRef<string | null>(null);
  const modeRef = useRef<Mode>("universe");

  const params = initialParams();
  const initialLayerNames = (params.get("edges") || "curated").split(",");
  const [layers, setLayers] = useState<Record<LayerName, boolean>>({
    curated: initialLayerNames.includes("curated"),
    membership: initialLayerNames.includes("membership"),
    similarity: initialLayerNames.includes("similarity")
  });
  const [mode, setMode] = useState<Mode>((params.get("mode") as Mode) || "universe");
  const [activeGalaxy, setActiveGalaxy] = useState(params.get("galaxy") || "");
  const [showSources, setShowSources] = useState(params.get("sources") === "1");
  const [depth, setDepth] = useState(Number(params.get("depth") || 1));
  const [k, setK] = useState(Number(params.get("k") || 3));
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [pathState, setPathState] = useState({ nodes: new Set<string>(), edges: new Set<string>() });
  const [status, setStatus] = useState("Loading graph…");
  const [relations, setRelations] = useState<Array<{ edge: string; type: string; node: GraphNode }>>([]);

  modeRef.current = mode;

  const toggleLayer = (layer: LayerName) => {
    setLayers((current) => ({ ...current, [layer]: !current[layer] }));
  };

  const updateUrl = (node?: GraphNode | null) => {
    if (typeof window === "undefined") return;
    const next = new URLSearchParams();
    next.set("mode", mode);
    const focus = node?.id || selected?.id;
    if (focus) next.set("focus", focus);
    if (activeGalaxy) next.set("galaxy", activeGalaxy);
    next.set("edges", Object.entries(layers).filter(([, value]) => value).map(([name]) => name).join(","));
    if (layers.similarity) next.set("k", String(k));
    if (mode === "neighborhood") next.set("depth", String(depth));
    if (showSources) next.set("sources", "1");
    window.history.replaceState(null, "", `${window.location.pathname}?${next}`);
  };

  function visibleNeighborhood(graph: Graph, focus: string, hopCount: number) {
    const visible = new Set([focus]);
    let frontier = new Set([focus]);
    for (let hop = 0; hop < hopCount; hop += 1) {
      const next = new Set<string>();
      for (const node of frontier) {
        for (const neighbor of graph.neighbors(node)) {
          visible.add(neighbor);
          next.add(neighbor);
        }
      }
      frontier = next;
    }
    return visible;
  }

  function applyVisibility(graph: Graph, focus: GraphNode | null) {
    let visible: Set<string> | null = null;
    if (mode === "neighborhood" && focus && graph.hasNode(focus.id)) {
      visible = visibleNeighborhood(graph, focus.id, depth);
    } else if (mode === "path" && pathState.nodes.size > 0) {
      visible = pathState.nodes;
    }

    graph.forEachNode((id, attributes) => {
      const node = attributes as GraphNode;
      const hiddenBySource = node.scope === "support" && !showSources;
      const hiddenByGalaxy = Boolean(mode === "galaxy" && activeGalaxy && node.galaxyId !== activeGalaxy);
      const hiddenByFocus = visible ? !visible.has(id) : false;
      graph.setNodeAttribute(id, "hidden", hiddenBySource || hiddenByGalaxy || hiddenByFocus);
      const focused = focus?.id === id || pathState.nodes.has(id);
      graph.setNodeAttribute(id, "selected", focused);
      graph.setNodeAttribute(
        id,
        "color",
        focused ? "#df7880" : node.scope === "support" ? "#7896ad" : node.color
      );
      graph.setNodeAttribute(id, "size", focused ? Math.max(8, node.size * 1.45) : node.scope === "support" ? Math.min(6, node.size) : node.size);
      graph.setNodeAttribute(
        id,
        "label",
        focused || node.isGalaxy || node.degree >= 8 ? node.originalLabel || node.label : ""
      );
      graph.setNodeAttribute(id, "zIndex", focused ? 12 : 0);
    });

    graph.forEachEdge((edge, attributes, source, target) => {
      const hidden = graph.getNodeAttribute(source, "hidden") || graph.getNodeAttribute(target, "hidden");
      graph.setEdgeAttribute(edge, "hidden", Boolean(hidden));
      if (pathState.edges.has(edge)) {
        graph.mergeEdgeAttributes(edge, { color: "#df7880", size: 2.1, zIndex: 10 });
      } else {
        graph.mergeEdgeAttributes(edge, {
          color: attributes.baseColor,
          size: attributes.baseSize,
          zIndex: 0
        });
      }
    });
  }

  function selectNode(id: string, graph = graphRef.current, sigma = renderer.current) {
    if (!graph || !graph.hasNode(id)) return;
    const attributes = graph.getNodeAttributes(id) as GraphNode;
    const node = { ...attributes, label: attributes.originalLabel || attributes.label };

    const currentMode = modeRef.current;

    if (node.isGalaxy) {
      setActiveGalaxy(node.galaxyId);
      modeRef.current = "galaxy";
      setMode("galaxy");
    } else if (currentMode === "galaxy") {
      setActiveGalaxy(node.galaxyId);
    }

    if (currentMode === "path" && !node.isGalaxy) {
      if (!pathStart.current) {
        pathStart.current = id;
        setPathState({ nodes: new Set([id]), edges: new Set() });
        setStatus(`Path start: ${node.label}. Select a destination.`);
      } else {
        const path = shortestPath(graph, pathStart.current, id);
        setPathState(path);
        setStatus(path.nodes.size > 1 ? `Path found across ${path.nodes.size} nodes.` : "No path found in the visible layers.");
        pathStart.current = null;
      }
    } else {
      setStatus(`${node.label} selected.`);
    }

    setSelected(node);
    const nodeRelations = graph.edges(id).slice(0, 12).map((edgeKey) => {
      const [source, target] = graph.extremities(edgeKey);
      const otherId = source === id ? target : source;
      return {
        edge: edgeKey,
        type: String(graph.getEdgeAttribute(edgeKey, "relationType") || "related_to"),
        node: graph.getNodeAttributes(otherId) as GraphNode
      };
    });
    setRelations(nodeRelations);

    if (sigma) {
      const coordinates = graph.getNodeAttributes(id);
      sigma.getCamera().animate({ x: coordinates.x, y: coordinates.y, ratio: node.isGalaxy ? 0.38 : 0.22 }, { duration: 420 });
    }
  }

  useEffect(() => {
    if (!container.current) return;
    let cancelled = false;
    setStatus("Loading graph…");

    Promise.all([
      fetch(`/Hugin${manifest.assets.graph}`).then((response) => response.json()),
      layers.similarity
        ? fetch(`/Hugin${manifest.assets.similarity}`).then((response) => response.json())
        : Promise.resolve([]),
      layers.membership
        ? fetch(`/Hugin${manifest.assets.membership}`).then((response) => response.json())
        : Promise.resolve([])
    ]).then(([payload, similarity, membership]) => {
      if (cancelled || !container.current) return;
      renderer.current?.kill();

      const graph = new Graph({ multi: true, type: "undirected" });
      payload.nodes.forEach((node: GraphNode) => graph.addNode(node.id, {
        ...node,
        label: node.isGalaxy || node.degree >= 8 ? node.label : "",
        originalLabel: node.label
      }));

      const addEdge = (edge: GraphEdge, color: string, size: number) => {
        if (!graph.hasNode(edge.source) || !graph.hasNode(edge.target) || edge.source === edge.target || graph.hasEdge(edge.id)) return;
        graph.addEdgeWithKey(edge.id, edge.source, edge.target, {
          color,
          baseColor: color,
          size,
          baseSize: size,
          relationType: edge.type,
          origin: edge.origin,
          score: edge.score
        });
      };

      if (layers.curated) payload.edges.forEach((edge: GraphEdge) => addEdge(edge, "#5e5867", 0.65));
      if (layers.membership) membership.forEach((edge: GraphEdge) => addEdge(edge, "#40384e", 0.22));
      if (layers.similarity) {
        similarity
          .filter((edge: GraphEdge) => Number(edge.rank) <= k)
          .forEach((edge: GraphEdge) => addEdge(edge, "#8567c566", 0.28));
      }

      graphRef.current = graph;
      const sigma = new Sigma(graph, container.current, {
        renderEdgeLabels: false,
        labelDensity: 0.05,
        labelGridCellSize: 100,
        labelRenderedSizeThreshold: 8,
        minCameraRatio: 0.04,
        maxCameraRatio: 6,
        zIndex: true
      });

      renderer.current = sigma;
      applyVisibility(graph, selected);
      sigma.on("clickNode", ({ node }) => selectNode(node, graph, sigma));
      sigma.on("enterNode", ({ node }) => {
        if (!graph.getNodeAttribute(node, "selected")) {
          graph.setNodeAttribute(node, "label", graph.getNodeAttribute(node, "originalLabel"));
          sigma.refresh();
        }
      });
      sigma.on("leaveNode", ({ node }) => {
        const attributes = graph.getNodeAttributes(node) as GraphNode;
        if (!attributes.isGalaxy && attributes.degree < 8 && !graph.getNodeAttribute(node, "selected")) {
          graph.setNodeAttribute(node, "label", "");
          sigma.refresh();
        }
      });

      const focus = initialParams().get("focus");
      if (focus && graph.hasNode(focus)) {
        selectNode(focus, graph, sigma);
      } else {
        setStatus(`${manifest.counts.coreEntities.toLocaleString()} knowledge nodes ready.`);
      }
    });

    return () => {
      cancelled = true;
      renderer.current?.kill();
    };
  }, [manifest, layers, k, showSources]);

  useEffect(() => {
    const graph = graphRef.current;
    if (!graph) return;
    applyVisibility(graph, selected);
    renderer.current?.refresh();
    updateUrl(selected);
  }, [mode, activeGalaxy, depth, pathState, selected, showSources]);

  const searchMatches = useMemo(() => {
    const graph = graphRef.current;
    if (!graph || query.trim().length < 2) return [];
    const normalized = query.trim().toLowerCase();
    const matches: GraphNode[] = [];
    graph.forEachNode((_id, attributes) => {
      const node = attributes as GraphNode;
      const haystack = `${node.originalLabel || node.label} ${node.category} ${node.kind}`.toLowerCase();
      if (haystack.includes(normalized) && (showSources || node.scope !== "support")) {
        matches.push({ ...node, label: node.originalLabel || node.label });
      }
    });
    return matches.sort((a, b) => b.degree - a.degree).slice(0, 6);
  }, [query, status, showSources]);

  function resetView() {
    modeRef.current = "universe";
    setMode("universe");
    setActiveGalaxy("");
    setSelected(null);
    setRelations([]);
    setPathState({ nodes: new Set(), edges: new Set() });
    pathStart.current = null;
    renderer.current?.getCamera().animatedReset({ duration: 420 });
    setStatus("Universe view restored.");
  }

  return (
    <div className="graph-page">
      <header className="graph-topbar">
        <div className="graph-title">
          <p className="eyebrow">Interactive knowledge map</p>
          <h1>HUGIN Universe</h1>
        </div>
        <p className="search-status" aria-live="polite">{status}</p>
      </header>

      <div className="graph-shell">
        <aside className="graph-rail" aria-label="Graph view controls">
          <fieldset>
            <legend>View</legend>
            {(["universe", "galaxy", "neighborhood", "path"] as Mode[]).map((value) => (
              <div className="graph-mode" key={value}>
                <input
                  id={`mode-${value}`}
                  type="radio"
                  name="graph-mode"
                  value={value}
                  checked={mode === value}
                  onChange={() => {
                    modeRef.current = value;
                    setMode(value);
                    if (value !== "path") {
                      pathStart.current = null;
                      setPathState({ nodes: new Set(), edges: new Set() });
                    }
                  }}
                />
                <label htmlFor={`mode-${value}`}>
                  <span>{value[0].toUpperCase() + value.slice(1)}</span>
                  <span aria-hidden="true">→</span>
                </label>
              </div>
            ))}
          </fieldset>

          <fieldset>
            <legend>Relationship layers</legend>
            <label className="layer-toggle">
              <input type="checkbox" checked={layers.curated} onChange={() => toggleLayer("curated")} />
              <span className="layer-key"></span>
              Curated
            </label>
            <label className="layer-toggle">
              <input type="checkbox" checked={layers.membership} onChange={() => toggleLayer("membership")} />
              <span className="layer-key membership"></span>
              Membership
            </label>
            <label className="layer-toggle">
              <input type="checkbox" checked={layers.similarity} onChange={() => toggleLayer("similarity")} />
              <span className="layer-key similarity"></span>
              Similarity
            </label>
            <label className="layer-toggle">
              <input type="checkbox" checked={showSources} onChange={() => setShowSources((value) => !value)} />
              <span className="layer-key sources"></span>
              Source layer
            </label>
          </fieldset>

          {mode === "neighborhood" && (
            <fieldset>
              <legend>Neighborhood depth</legend>
              <select aria-label="Neighborhood depth" value={depth} onChange={(event) => setDepth(Number(event.target.value))}>
                <option value={1}>One hop</option>
                <option value={2}>Two hops</option>
              </select>
            </fieldset>
          )}

          {layers.similarity && (
            <fieldset>
              <legend>Similarity density</legend>
              <select aria-label="Similarity density" value={k} onChange={(event) => setK(Number(event.target.value))}>
                <option value={3}>Top 3 neighbors</option>
                <option value={5}>Top 5 neighbors</option>
                <option value={8}>Top 8 neighbors</option>
              </select>
            </fieldset>
          )}
        </aside>

        <div className="graph-stage">
          <div className="graph-controls">
            <input
              aria-label="Find a graph node"
              placeholder="Find a node…"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && searchMatches[0]) selectNode(searchMatches[0].id);
              }}
            />
            <button className="button" type="button" onClick={resetView}>Reset view</button>
            <a className="button" href="/Hugin/explore/">Catalog</a>
          </div>

          {searchMatches.length > 0 && (
            <div className="search-results" style={{ position: "absolute", zIndex: 7, top: 62, left: 14, width: "min(420px, calc(100% - 28px))", background: "var(--ink-raised)" }}>
              {searchMatches.map((node) => (
                <button
                  className="search-result"
                  style={{ width: "100%", color: "inherit", textAlign: "left", borderRight: 0, borderBottom: 0, borderLeft: 0, background: "transparent" }}
                  type="button"
                  onClick={() => {
                    selectNode(node.id);
                    setQuery("");
                  }}
                  key={node.id}
                >
                  <strong>{node.label}</strong>
                  <p>{node.kind} · {node.galaxyId}</p>
                </button>
              ))}
            </div>
          )}

          <div
            ref={container}
            style={{ width: "100%", height: "100%" }}
            role="img"
            aria-label={`Interactive WebGL map of ${manifest.counts.coreEntities.toLocaleString()} HUGIN knowledge nodes`}
          />
          <p className="graph-hint">
            Scroll to zoom · drag to navigate · select a node to inspect · Path mode uses two selections
          </p>
        </div>

        <aside className="inspector" aria-live="polite">
          {selected ? (
            <>
              <p className="eyebrow">{selected.kind} · {selected.galaxyId}</p>
              <h2>{selected.label}</h2>
              <p className="inspector-summary">{selected.summary}</p>
              <dl>
                <dt>ID</dt><dd>{selected.id}</dd>
                <dt>Category</dt><dd>{selected.category}</dd>
                <dt>Relations</dt><dd>{selected.degree.toLocaleString()}</dd>
                <dt>Layer</dt><dd>{selected.scope}</dd>
              </dl>
              <div className="actions">
                <a className="button primary" href={`/Hugin${selected.route}`}>
                  Open {selected.isGalaxy ? "catalog" : "record"}
                </a>
                {!selected.isGalaxy && (
                  <button
                    className="button"
                    type="button"
                    onClick={() => {
                      modeRef.current = "neighborhood";
                      setMode("neighborhood");
                    }}
                  >
                    Neighborhood
                  </button>
                )}
              </div>
              {relations.length > 0 && (
                <>
                  <p className="meta-label" style={{ marginTop: 26 }}>Visible relations</p>
                  <ul className="inspector-relations">
                    {relations.map(({ edge, type, node }) => (
                      <li key={edge}>
                        <strong>{node.originalLabel || node.label}</strong>
                        {type.replace(/_/g, " ")}
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </>
          ) : (
            <>
              <p className="eyebrow">Universe inspector</p>
              <h2>{manifest.counts.coreEntities.toLocaleString()} knowledge nodes</h2>
              <p className="inspector-summary">
                Start with the complete universe, isolate a galaxy, inspect a neighborhood,
                or trace a path between two records.
              </p>
              <dl>
                <dt>Curated edges</dt><dd>{manifest.counts.curatedRelations.toLocaleString()}</dd>
                <dt>Galaxies</dt><dd>{manifest.counts.galaxies}</dd>
                <dt>Optional sources</dt><dd>{manifest.counts.supportEntities.toLocaleString()}</dd>
                <dt>Evidence</dt><dd>{manifest.counts.evidenceRecords.toLocaleString()} on demand</dd>
              </dl>
              <a href="/Hugin/explore/">Open accessible catalog →</a>
            </>
          )}
        </aside>
      </div>
    </div>
  );
}
