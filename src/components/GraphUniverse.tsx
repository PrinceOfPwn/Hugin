import { useEffect, useRef, useState } from "react";
import Graph from "graphology";
import Sigma from "sigma";
import type { DatasetManifest } from "../lib/types";

type GraphNode = { id: string; label: string; kind: string; galaxyId: string; category: string; route: string; x: number; y: number; size: number; color: string; isGalaxy?: boolean };

export default function GraphUniverse({ manifest }: { manifest: DatasetManifest }) {
  const container = useRef<HTMLDivElement>(null);
  const renderer = useRef<Sigma | null>(null);
  const graphRef = useRef<Graph | null>(null);
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const initialEdges = typeof location === "undefined" ? ["curated"] : (new URLSearchParams(location.search).get("edges") || "curated").split(",");
  const [layers, setLayers] = useState({ curated: initialEdges.includes("curated"), membership: initialEdges.includes("membership"), similarity: initialEdges.includes("similarity") });
  const [k, setK] = useState(3);
  const [mode, setMode] = useState("universe");
  const pathStart = useRef<string | null>(null);

  const toggleLayer = (layer: keyof typeof layers) => setLayers((current) => ({ ...current, [layer]: !current[layer] }));

  useEffect(() => {
    if (!container.current) return;
    Promise.all([
      fetch(`/Hugin${manifest.assets.graph}`).then((response) => response.json()),
      layers.similarity ? fetch(`/Hugin${manifest.assets.similarity}`).then((response) => response.json()) : Promise.resolve([]),
      layers.membership ? fetch(`/Hugin${manifest.assets.membership}`).then((response) => response.json()) : Promise.resolve([])
    ]).then(([payload, similarity, membership]) => {
      renderer.current?.kill();
      const graph = new Graph({ multi: true, type: "undirected" });
      payload.nodes.forEach((node: GraphNode) => graph.addNode(node.id, node));
      if (layers.curated) payload.edges.forEach((edge: any) => { if (graph.hasNode(edge.source) && graph.hasNode(edge.target) && edge.source !== edge.target) graph.addEdgeWithKey(edge.id, edge.source, edge.target, { color: "#8e8798", size: .7, type: "line", origin: "curated" }); });
      if (layers.membership) membership.forEach((edge: any) => { if (graph.hasNode(edge.source) && graph.hasNode(edge.target)) graph.addEdgeWithKey(edge.id, edge.source, edge.target, { color: "#ffffff12", size: .18, type: "line", origin: "membership" }); });
      if (layers.similarity) similarity.filter((edge: any) => edge.rank <= k).forEach((edge: any) => { if (!graph.hasEdge(edge.id)) graph.addEdgeWithKey(edge.id, edge.source, edge.target, { color: "#9d7bff55", size: .28, type: "dashed", origin: "similarity", score: edge.score }); });
      graphRef.current = graph;
      const sigma = new Sigma(graph, container.current!, { renderEdgeLabels: false, labelDensity: .06, labelGridCellSize: 90, minCameraRatio: .05, maxCameraRatio: 8, defaultEdgeColor: "#4b4455" });
      sigma.on("clickNode", ({ node }) => {
        const data = graph.getNodeAttributes(node) as GraphNode;
        setSelected(data);
        const params = new URLSearchParams(location.search); params.set("focus", node); params.set("edges", Object.entries(layers).filter(([, active]) => active).map(([name]) => name).join(",")); params.set("k", String(k)); history.replaceState(null, "", `${location.pathname}?${params}`);
        if (mode === "neighborhood") {
          const visible = new Set([node, ...graph.neighbors(node)]);
          graph.forEachNode((id) => graph.setNodeAttribute(id, "hidden", !visible.has(id)));
        } else if (mode === "galaxy") {
          graph.forEachNode((id, attributes) => graph.setNodeAttribute(id, "hidden", attributes.galaxyId !== data.galaxyId));
        } else if (mode === "path") {
          if (!pathStart.current) pathStart.current = node;
          else {
            const queue = [pathStart.current]; const previous = new Map<string, string | null>([[pathStart.current, null]]);
            while (queue.length && !previous.has(node)) { const current = queue.shift()!; for (const neighbor of graph.neighbors(current)) if (!previous.has(neighbor)) { previous.set(neighbor, current); queue.push(neighbor); } }
            const visible = new Set<string>(); let cursor: string | null | undefined = node; while (cursor) { visible.add(cursor); cursor = previous.get(cursor); }
            graph.forEachNode((id) => graph.setNodeAttribute(id, "hidden", !visible.has(id))); pathStart.current = null;
          }
        }
      });
      renderer.current = sigma;
      const focus = new URLSearchParams(location.search).get("focus");
      if (focus && graph.hasNode(focus)) { setSelected(graph.getNodeAttributes(focus) as GraphNode); sigma.getCamera().animate(graph.getNodeAttributes(focus), { duration: 500 }); }
      const galaxy = new URLSearchParams(location.search).get("galaxy");
      if (galaxy) graph.forEachNode((id, attributes) => graph.setNodeAttribute(id, "hidden", attributes.galaxyId !== galaxy));
    });
    return () => renderer.current?.kill();
  }, [manifest, layers, k, mode]);

  return <div className="graph-shell">
    <div className="graph-canvas">
      <div className="graph-controls" aria-label="Graph controls">
        <select aria-label="View mode" value={mode} onChange={(event) => setMode(event.target.value)}><option value="universe">Universe</option><option value="galaxy">Galaxy</option><option value="neighborhood">Neighborhood</option><option value="path">Path</option></select>
        <button aria-pressed={layers.curated} onClick={() => toggleLayer("curated")}>Original</button>
        <button aria-pressed={layers.membership} onClick={() => toggleLayer("membership")}>Membership</button>
        <button aria-pressed={layers.similarity} onClick={() => toggleLayer("similarity")}>Similarity</button>
        <select aria-label="Similarity density" value={k} onChange={(event) => setK(Number(event.target.value))}>{[3, 5, 8].map((value) => <option value={value} key={value}>Top {value} neighbors</option>)}</select>
        <a className="button" href={`/Hugin/flight/${selected ? `?galaxy=${selected.galaxyId}` : ""}`}>Raven Flight</a>
      </div>
      <div ref={container} style={{width: "100%", height: "100%"}} role="img" aria-label="Interactive WebGL map of 5,608 HUGIN entities" />
    </div>
    <aside className="inspector" aria-live="polite">
      {selected ? <><p className="eyebrow">{selected.kind} · {selected.galaxyId}</p><h2>{selected.label}</h2><dl><dt>ID</dt><dd>{selected.id}</dd><dt>Category</dt><dd>{selected.category}</dd></dl><a className="button primary" href={`/Hugin${selected.route}`}>Open {selected.isGalaxy ? "galaxy catalog" : "entity"}</a></> : <><p className="eyebrow">Universe inspector</p><h2>5,608 entities</h2><p>Select any star to inspect its metadata and open the permanent, accessible detail page.</p><p>Solid lines are curated. Faint lines are structural membership. Violet generated links are semantic similarity and remain explicitly labeled.</p><a href="/Hugin/explore/">Open accessible catalog →</a></>}
    </aside>
  </div>;
}
