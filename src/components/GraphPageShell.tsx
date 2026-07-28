import { useEffect, useMemo, useRef, useState } from "react";
import type { DatasetManifest, Entity } from "../lib/types";
import { decodeFilters, encodeFilters, EMPTY_FILTER, filterEntities, type FilterState } from "../lib/filters";
import FilterSidebar from "./FilterSidebar";
import GraphThreeV3 from "./GraphThreeV3";
import type { UniverseSettings } from "./UniverseControls";

const DEFAULT_UNIVERSE_SETTINGS: UniverseSettings = {
  edgesMode: "selected",
  autoOrbit: true,
  cinematic: true,
};

// GraphThreeV3 already accepts loose GraphDataIn — we mirror the props shape.
interface Props {
  graphData: any;
  manifest: DatasetManifest;
  entities: Entity[];
}

export default function GraphPageShell({ graphData, manifest, entities }: Props) {
  const [filter, setFilter] = useState<FilterState>(() => {
    if (typeof window === "undefined") return EMPTY_FILTER;
    return decodeFilters(window.location.search);
  });
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [universe, setUniverse] = useState<UniverseSettings>(DEFAULT_UNIVERSE_SETTINGS);

  // ─── URL sync (debounced 500ms) ───────────────────────────────────────────
  const syncTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (typeof window === "undefined") return;
    if (syncTimer.current) clearTimeout(syncTimer.current);
    syncTimer.current = setTimeout(() => {
      const qs = encodeFilters(filter);
      window.history.replaceState(null, "", `${window.location.pathname}${qs}`);
    }, 500);
    return () => { if (syncTimer.current) clearTimeout(syncTimer.current); };
  }, [filter]);

  // ─── Compute filtered id set ──────────────────────────────────────────────
  const filteredIds = useMemo<Set<string> | null>(() => {
    const anyActive =
      filter.timeWindow !== "all" ||
      filter.galaxies.size || filter.tiers.size || filter.kinds.size ||
      filter.tags.size || filter.categories.size || filter.mitre.size ||
      filter.massMin > 0 || filter.query.trim().length > 0;
    if (!anyActive) return null; // nothing filtered — no dimming
    const keep = new Set<string>();
    for (const e of filterEntities(entities, filter)) keep.add(e.id);
    return keep;
  }, [entities, filter]);

  const totalNodes = entities.length;
  const activeCount = filteredIds ? filteredIds.size : totalNodes;

  return (
    <div style={{ display: "flex", width: "100%", height: "100vh", background: "#000005", position: "relative" }}>
      {/* Filter sidebar (collapsible) */}
      {sidebarOpen && (
        <div style={{ flex: "0 0 auto", height: "100vh" }}>
          <FilterSidebar
            entities={entities}
            filter={filter}
            onChange={setFilter}
            storageKey="hugin.filterSidebar.sectionState"
          />
        </div>
      )}

      {/* Toggle button */}
      <button
        onClick={() => setSidebarOpen((v) => !v)}
        title={sidebarOpen ? "Hide filters" : "Show filters"}
        style={{
          position: "absolute",
          top: 10,
          left: sidebarOpen ? 328 : 8,
          zIndex: 20,
          background: "rgba(0,8,20,0.85)",
          border: "1px solid rgba(0,240,255,0.3)",
          color: "#00f0ff",
          fontFamily: "monospace", fontSize: 11,
          padding: "4px 10px", cursor: "pointer",
          transition: "left 0.2s ease",
        }}
      >
        {sidebarOpen ? "◀ Filters" : "Filters ▶"}
      </button>

      {/* Filter status bar (only when active) */}
      {filteredIds && (
        <div style={{
          position: "absolute", top: 10,
          left: sidebarOpen ? 420 : 90, zIndex: 20,
          background: "rgba(0,8,20,0.75)",
          border: "1px solid rgba(0,240,255,0.2)",
          color: "#c8d4e8",
          fontFamily: "monospace", fontSize: 11,
          padding: "4px 10px",
        }}>
          {activeCount.toLocaleString()} / {totalNodes.toLocaleString()} nodes match
        </div>
      )}

      {/* Graph */}
      <div style={{ flex: 1, minWidth: 0, height: "100vh" }}>
        <GraphThreeV3
          graphData={graphData}
          manifest={manifest}
          filteredIds={filteredIds}
          universe={universe}
          onUniverseChange={setUniverse}
        />
      </div>
    </div>
  );
}
