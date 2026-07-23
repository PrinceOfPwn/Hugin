import { useEffect, useMemo, useState } from "react";
import type { DatasetManifest, Entity } from "../lib/types";

export default function CatalogExplorer({ manifest }: { manifest: DatasetManifest }) {
  const [entities, setEntities] = useState<Entity[]>([]);
  const initialParams = () => new URLSearchParams(typeof location === "undefined" ? "" : location.search);
  const [query, setQuery] = useState(() => initialParams().get("q") || "");
  const [kind, setKind] = useState(() => initialParams().get("kind") || "all");
  const [galaxy, setGalaxy] = useState(() => initialParams().get("galaxy") || "all");
  const [limit, setLimit] = useState(120);

  useEffect(() => { fetch(`/Hugin${manifest.assets.catalog}`).then((response) => response.json()).then(setEntities); }, [manifest]);
  useEffect(() => {
    const params = new URLSearchParams();
    if (query) params.set("q", query); if (kind !== "all") params.set("kind", kind); if (galaxy !== "all") params.set("galaxy", galaxy);
    if (typeof history !== "undefined") history.replaceState(null, "", `${location.pathname}${params.size ? `?${params}` : ""}`);
  }, [query, kind, galaxy]);

  const filtered = useMemo(() => entities.filter((entity) => {
    const text = `${entity.title} ${entity.summary} ${entity.tags.join(" ")} ${entity.mitre.join(" ")}`.toLowerCase();
    return (kind === "all" || entity.kind === kind) && (galaxy === "all" || entity.galaxyId === galaxy) && (!query || text.includes(query.toLowerCase()));
  }), [entities, query, kind, galaxy]);
  const kinds = [...new Set(entities.map((entity) => entity.kind))].sort();
  const galaxies = [...new Set(entities.map((entity) => entity.galaxyId))].sort();

  return <div className="panel">
    <div className="toolbar">
      <input aria-label="Filter catalog" placeholder="Filter 5,608 entities…" value={query} onChange={(event) => { setQuery(event.target.value); setLimit(120); }} />
      <select aria-label="Filter by type" value={kind} onChange={(event) => setKind(event.target.value)}><option value="all">All types</option>{kinds.map((value) => <option key={value}>{value}</option>)}</select>
      <select aria-label="Filter by galaxy" value={galaxy} onChange={(event) => setGalaxy(event.target.value)}><option value="all">All galaxies</option>{galaxies.map((value) => <option key={value}>{value}</option>)}</select>
    </div>
    <p style={{padding: "0 18px", color: "var(--muted)"}} aria-live="polite">{entities.length ? `${filtered.length.toLocaleString()} results` : "Loading catalog…"}</p>
    <div className="results">
      {filtered.slice(0, limit).map((entity) => <a className="result" href={`/Hugin${entity.route}`} key={entity.id}>
        <span><h3>{entity.title}</h3><p>{entity.summary}</p></span><span className="badge">{entity.kind}</span>
      </a>)}
    </div>
    {limit < filtered.length && <div style={{padding: 18, textAlign: "center"}}><button className="button" onClick={() => setLimit((value) => value + 120)}>Load 120 more</button></div>}
  </div>;
}
