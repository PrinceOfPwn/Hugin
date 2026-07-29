import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type * as THREE from "three";
import type { DatasetManifest, Entity } from "../lib/types";
import { decodeFilters, encodeFilters, EMPTY_FILTER, filterEntities, type FilterState } from "../lib/filters";
import FilterSidebar from "./FilterSidebar";
import GraphThreeV3 from "./GraphThreeV3";
import type { UniverseSettings } from "./UniverseControls";
import Breadcrumb from "./Breadcrumb";
import Minimap from "./Minimap";
import CommandPalette from "./CommandPalette";
import WelcomeTour from "./WelcomeTour";
import AffordanceHint from "./AffordanceHint";

const DEFAULT_UNIVERSE_SETTINGS: UniverseSettings = {
  edgesMode: "selected",
  autoOrbit: true,
  cinematic: true,
};

// Human-readable galaxy labels — mirrors GraphThreeV3.GALAXY_LABELS.
const GALAXY_LABELS: Record<string, string> = {
  techniques: "Techniques", internals: "Internals", defenses: "Defenses",
  chains: "Attack Chains", evidence: "Evidence", sources: "Sources",
  gaps: "Gaps", architecture: "Architecture", tradecraft_qa: "Q&A",
};

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

  // Ronda I: lifted selection + camera state for discoverability chrome.
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedGalaxyId, setSelectedGalaxyId] = useState<string | null>(null);
  const [teleportTarget, setTeleportTarget] = useState<{ x: number; z: number; nonce: number } | null>(null);
  const [externalSelectId, setExternalSelectId] = useState<string | null>(null);
  const cameraRef = useRef<THREE.Camera | null>(null);

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

  // Entity map for O(1) title/id lookup from breadcrumb + palette.
  const entityById = useMemo(() => {
    const m = new Map<string, Entity>();
    for (const e of entities) m.set(e.id, e);
    return m;
  }, [entities]);

  // Entities passed to Minimap + CommandPalette respect the current filter.
  const visibleEntities = useMemo<Entity[]>(() => {
    if (!filteredIds) return entities;
    const out: Entity[] = [];
    for (const e of entities) if (filteredIds.has(e.id)) out.push(e);
    return out;
  }, [entities, filteredIds]);

  const selectedEntity = selectedNodeId ? entityById.get(selectedNodeId) ?? null : null;
  const selectedGalaxyLabel = selectedGalaxyId
    ? (GALAXY_LABELS[selectedGalaxyId] ?? selectedGalaxyId)
    : (selectedEntity ? (GALAXY_LABELS[selectedEntity.galaxyId] ?? selectedEntity.galaxyId) : null);

  // ─── Handlers wired into GraphThreeV3 ─────────────────────────────────────
  const handleResetFocus = useCallback(() => {
    setSelectedNodeId(null);
    setSelectedGalaxyId(null);
    // Teleport camera back near universe origin.
    setTeleportTarget({ x: 0, z: 0, nonce: performance.now() });
  }, []);

  const handleClearNode = useCallback(() => {
    // "Click galaxy" in breadcrumb: drop node selection, keep galaxy focus.
    setSelectedNodeId(null);
    setExternalSelectId(null);
  }, []);

  const handleTeleport = useCallback((x: number, z: number) => {
    setTeleportTarget({ x, z, nonce: performance.now() });
  }, []);

  const handleSelectFromPalette = useCallback((entity: Entity) => {
    setSelectedNodeId(entity.id);
    setSelectedGalaxyId(entity.galaxyId);
    // Bump nonce via unique object so the child effect re-fires even if the
    // id is the same as last time.
    setExternalSelectId(entity.id + ":" + performance.now());
  }, []);

  // Pass the nonce-suffixed string to the child so its effect re-fires on
  // every palette pick, even when the same id is selected twice in a row.
  // Child splits off the id before using it.

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
          border: "1px solid rgba(157,124,244,0.32)",
          color: "var(--nav-accent)",
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
          border: "1px solid rgba(157,124,244,0.24)",
          color: "#c8d4e8",
          fontFamily: "monospace", fontSize: 11,
          padding: "4px 10px",
        }}>
          {activeCount.toLocaleString()} / {totalNodes.toLocaleString()} nodes match
        </div>
      )}

      {/* Graph */}
      <div style={{ flex: 1, minWidth: 0, height: "100vh", position: "relative" }}>
        <GraphThreeV3
          graphData={graphData}
          manifest={manifest}
          filteredIds={filteredIds}
          universe={universe}
          onUniverseChange={setUniverse}
          cameraRef={cameraRef}
          teleportTarget={teleportTarget}
          onNodeSelect={(id) => {
            setSelectedNodeId(id);
            if (id) {
              const ent = entityById.get(id);
              if (ent) setSelectedGalaxyId(ent.galaxyId);
            }
          }}
          onGalaxySelect={setSelectedGalaxyId}
          externalSelectId={externalSelectId}
        />

        {/* Discoverability overlays (Ronda I) */}
        <Breadcrumb
          galaxyLabel={selectedGalaxyLabel}
          nodeLabel={selectedEntity?.title ?? null}
          onReset={handleResetFocus}
          onGalaxyClick={handleClearNode}
        />
        <Minimap entities={visibleEntities} cameraRef={cameraRef} onTeleport={handleTeleport} />
        <CommandPalette entities={visibleEntities} onSelect={handleSelectFromPalette} />
        <AffordanceHint />
        <WelcomeTour />
        <a
          href="/Hugin/explore/"
          style={{
            position: "absolute", right: 16, bottom: 16, zIndex: 25,
            padding: "8px 12px", border: "1px solid rgba(157,124,244,0.35)",
            background: "rgba(0,8,20,0.82)", color: "var(--nav-accent)",
            fontFamily: "monospace", fontSize: 11, textDecoration: "none",
          }}
        >
          Open accessible catalog →
        </a>
      </div>
    </div>
  );
}
