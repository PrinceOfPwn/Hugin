import { useEffect, useMemo, useState } from "react";
import type { DatasetManifest, Entity } from "../lib/types";

function initialParams() {
  return new URLSearchParams(typeof window === "undefined" ? "" : window.location.search);
}

export default function CatalogExplorer({ manifest }: { manifest: DatasetManifest }) {
  const params = initialParams();
  const [entities, setEntities] = useState<Entity[]>([]);
  const [query, setQuery] = useState(params.get("q") || "");
  const [kind, setKind] = useState(params.get("kind") || "all");
  const [galaxy, setGalaxy] = useState(params.get("galaxy") || "all");
  const [includeSources, setIncludeSources] = useState(params.get("sources") === "1");
  const [limit, setLimit] = useState(100);

  useEffect(() => {
    fetch(`/Hugin${manifest.assets.catalog}`)
      .then((response) => response.json())
      .then(setEntities);
  }, [manifest]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const next = new URLSearchParams();
    if (query) next.set("q", query);
    if (kind !== "all") next.set("kind", kind);
    if (galaxy !== "all") next.set("galaxy", galaxy);
    if (includeSources) next.set("sources", "1");
    window.history.replaceState(null, "", `${window.location.pathname}${next.size ? `?${next}` : ""}`);
  }, [query, kind, galaxy, includeSources]);

  const visibleEntities = useMemo(
    () => entities.filter((entity) => includeSources || entity.publishState === "core"),
    [entities, includeSources]
  );

  const filtered = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return visibleEntities
      .filter((entity) => {
        const text = [
          entity.title,
          entity.summary,
          entity.tags.join(" "),
          entity.mitre.join(" "),
          entity.category
        ].join(" ").toLowerCase();
        return (kind === "all" || entity.kind === kind)
          && (galaxy === "all" || entity.galaxyId === galaxy)
          && (!normalizedQuery || text.includes(normalizedQuery));
      })
      .sort((a, b) => b.degree - a.degree || a.title.localeCompare(b.title));
  }, [visibleEntities, query, kind, galaxy]);

  const kinds = [...new Set(visibleEntities.map((entity) => entity.kind))].sort();
  const galaxies = [...new Set(visibleEntities.map((entity) => entity.galaxyId))].sort();

  return (
    <div className="catalog-shell">
      <div className="catalog-toolbar">
        <input
          aria-label="Filter catalog"
          placeholder={`Filter ${manifest.counts.coreEntities.toLocaleString()} knowledge nodes…`}
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setLimit(100);
          }}
        />
        <select aria-label="Filter by type" value={kind} onChange={(event) => setKind(event.target.value)}>
          <option value="all">All entity types</option>
          {kinds.map((value) => <option value={value} key={value}>{value.replace(/_/g, " ")}</option>)}
        </select>
        <select aria-label="Filter by galaxy" value={galaxy} onChange={(event) => setGalaxy(event.target.value)}>
          <option value="all">All galaxies</option>
          {galaxies.map((value) => <option value={value} key={value}>{value}</option>)}
        </select>
        <label className="layer-toggle" style={{ border: "1px solid var(--rule)" }}>
          <input
            type="checkbox"
            checked={includeSources}
            onChange={() => setIncludeSources((value) => !value)}
          />
          Include source layer
        </label>
      </div>

      <p className="catalog-summary" aria-live="polite">
        <span>{entities.length ? `${filtered.length.toLocaleString()} matching nodes` : "Loading catalog…"}</span>
        <span>{includeSources ? "Knowledge + anonymous sources" : "Knowledge layer only"}</span>
      </p>

      <div>
        {filtered.slice(0, limit).map((entity) => (
          <a className="catalog-result" href={`/Hugin${entity.route}`} key={entity.id}>
            <span>
              <h3>{entity.title}</h3>
              <p>{entity.summary}</p>
            </span>
            <span className="catalog-galaxy">{entity.galaxyId}</span>
            <span className="catalog-kind">{entity.kind.replace(/_/g, " ")}</span>
          </a>
        ))}
      </div>

      {limit < filtered.length && (
        <div className="load-more">
          <button className="button" type="button" onClick={() => setLimit((value) => value + 100)}>
            Load 100 more
          </button>
        </div>
      )}
    </div>
  );
}
