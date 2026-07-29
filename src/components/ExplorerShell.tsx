import {
  useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState,
  type CSSProperties, type MouseEvent,
} from "react";
import type { Entity, Galaxy, Relation } from "../lib/types";
import {
  decodeFilters, encodeFilters, EMPTY_FILTER, filterEntities,
  type FilterState, type SortBy, type SortDir,
} from "../lib/filters";
import FilterSidebar from "./FilterSidebar";
import EntityListCard from "./EntityListCard";
import EntityPreviewPane from "./EntityPreviewPane";

interface Props {
  entities?: Entity[];
  galaxies: Galaxy[];
  relations?: Relation[]; // may be omitted; preview then shows no "related"
  routePrefix: string;    // e.g. "/Hugin"
  dataUrls?: { catalog: string; graph: string };
}

// URL param names for view-mode and selection — namespaced so they don't collide.
const URL_VIEW = "view";
const URL_SEL = "sel";

// Virtualization threshold + row heights.
const VIRTUALIZE_ABOVE = 200;
const LIST_ITEM_H = 96;        // approx card height in list mode
const GRID_ROW_H = 168;        // approx row height in grid mode (rows of 2)
const GRID_COLS = 2;

export default function ExplorerShell({
  entities: initialEntities = [],
  galaxies,
  relations: initialRelations = [],
  routePrefix,
  dataUrls,
}: Props) {
  const [remoteData, setRemoteData] = useState<{ entities: Entity[]; relations: Relation[] } | null>(
    initialEntities.length ? { entities: initialEntities, relations: initialRelations } : null,
  );
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    if (remoteData || !dataUrls) return;
    const controller = new AbortController();
    Promise.all([
      fetch(dataUrls.catalog, { signal: controller.signal }).then((r) => {
        if (!r.ok) throw new Error(`catalog ${r.status}`);
        return r.json();
      }),
      fetch(dataUrls.graph, { signal: controller.signal }).then((r) => {
        if (!r.ok) throw new Error(`graph ${r.status}`);
        return r.json();
      }),
    ]).then(([entities, graph]) => {
      setRemoteData({ entities, relations: graph.edges ?? [] });
    }).catch((error) => {
      if (error?.name !== "AbortError") setLoadError(String(error?.message ?? error));
    });
    return () => controller.abort();
  }, [dataUrls, remoteData]);

  const entities = remoteData?.entities ?? initialEntities;
  const relations = remoteData?.relations ?? initialRelations;
  const initialQs = typeof window === "undefined" ? "" : window.location.search;
  const initialParams = new URLSearchParams(initialQs.startsWith("?") ? initialQs.slice(1) : initialQs);

  const [filter, setFilter] = useState<FilterState>(() =>
    typeof window === "undefined" ? EMPTY_FILTER : decodeFilters(initialQs)
  );
  const [viewMode, setViewMode] = useState<"grid" | "list">(
    (initialParams.get(URL_VIEW) as "grid" | "list") === "grid" ? "grid" : "list"
  );
  const [selectedId, setSelectedId] = useState<string | null>(
    initialParams.get(URL_SEL) || null
  );

  // ─── URL sync (debounced) ─────────────────────────────────────────────────
  const syncTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (typeof window === "undefined") return;
    if (syncTimer.current) clearTimeout(syncTimer.current);
    syncTimer.current = setTimeout(() => {
      const base = encodeFilters(filter);
      const p = new URLSearchParams(base.startsWith("?") ? base.slice(1) : base);
      if (viewMode !== "list") p.set(URL_VIEW, viewMode);
      if (selectedId) p.set(URL_SEL, selectedId);
      const qs = p.toString();
      window.history.replaceState(null, "", `${window.location.pathname}${qs ? `?${qs}` : ""}`);
    }, 400);
    return () => { if (syncTimer.current) clearTimeout(syncTimer.current); };
  }, [filter, viewMode, selectedId]);

  // ─── Lookup helpers ───────────────────────────────────────────────────────
  const galaxyNameMap = useMemo(() => {
    const m = new Map<string, string>();
    for (const g of galaxies) m.set(g.id, g.name);
    return m;
  }, [galaxies]);

  const entitiesById = useMemo(() => {
    const m = new Map<string, Entity>();
    for (const e of entities) m.set(e.id, e);
    return m;
  }, [entities]);

  const results = useMemo(() => filterEntities(entities, filter), [entities, filter]);

  const resultsIndexById = useMemo(() => {
    const m = new Map<string, number>();
    results.forEach((e, i) => m.set(e.id, i));
    return m;
  }, [results]);

  // If the current selection is filtered out, drop it.
  useEffect(() => {
    if (selectedId && !resultsIndexById.has(selectedId)) {
      // Do not clear if it's an unfiltered valid entity — user may want it visible in preview
      // But easier UX: clear.
      setSelectedId(null);
    }
  }, [resultsIndexById, selectedId]);

  const selectedEntity = selectedId ? entitiesById.get(selectedId) || null : null;

  // ─── Keyboard nav ─────────────────────────────────────────────────────────
  const searchInputRef = useRef<HTMLInputElement | null>(null);
  const listContainerRef = useRef<HTMLDivElement | null>(null);

  const focusSearch = useCallback(() => {
    // Find the sidebar's first input — the search input is section #1.
    const el = document.querySelector<HTMLInputElement>('aside input[placeholder^="title"]');
    if (el) { el.focus(); el.select(); }
  }, []);

  const moveSelection = useCallback((dir: 1 | -1) => {
    if (!results.length) return;
    const cur = selectedId ? resultsIndexById.get(selectedId) ?? -1 : -1;
    let next = cur + dir;
    if (next < 0) next = 0;
    if (next >= results.length) next = results.length - 1;
    setSelectedId(results[next].id);
  }, [results, resultsIndexById, selectedId]);

  useEffect(() => {
    const onKey = (ev: KeyboardEvent) => {
      const target = ev.target as HTMLElement | null;
      const isTyping = target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable);

      if (ev.key === "/" && !isTyping) {
        ev.preventDefault();
        focusSearch();
        return;
      }
      if (ev.key === "Escape") {
        if (isTyping && target?.tagName === "INPUT") {
          const input = target as HTMLInputElement;
          if (input.placeholder && input.placeholder.startsWith("title")) {
            setFilter((f) => ({ ...f, query: "" }));
            input.blur();
            return;
          }
        }
        setSelectedId(null);
        return;
      }
      if (isTyping) return;

      if (ev.key === "ArrowDown") { ev.preventDefault(); moveSelection(1); }
      else if (ev.key === "ArrowUp") { ev.preventDefault(); moveSelection(-1); }
      else if (ev.key === "Enter") {
        if (selectedEntity) {
          ev.preventDefault();
          window.location.href = `${routePrefix}${selectedEntity.route}`;
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [moveSelection, selectedEntity, focusSearch, routePrefix]);

  // ─── Selection click handler ──────────────────────────────────────────────
  const handleCardClick = useCallback((id: string, ev: MouseEvent) => {
    if (ev.metaKey || ev.ctrlKey || ev.button === 1) {
      // Cmd/Ctrl-click → let browser open in new tab (do not preventDefault).
      return;
    }
    ev.preventDefault();
    setSelectedId(id);
  }, []);

  // Auto-scroll selected into view.
  const rowsPerCol = viewMode === "grid" ? GRID_COLS : 1;
  const rowHeight = viewMode === "grid" ? GRID_ROW_H : LIST_ITEM_H;

  useLayoutEffect(() => {
    if (!selectedId || !listContainerRef.current) return;
    const idx = resultsIndexById.get(selectedId);
    if (idx == null) return;
    const rowIdx = Math.floor(idx / rowsPerCol);
    const scroller = listContainerRef.current;
    const top = rowIdx * rowHeight;
    const bottom = top + rowHeight;
    const viewTop = scroller.scrollTop;
    const viewBottom = viewTop + scroller.clientHeight;
    if (top < viewTop) scroller.scrollTop = top;
    else if (bottom > viewBottom) scroller.scrollTop = bottom - scroller.clientHeight;
  }, [selectedId, resultsIndexById, rowsPerCol, rowHeight]);

  // ─── Virtualization ───────────────────────────────────────────────────────
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportH, setViewportH] = useState(600);
  const virtualize = results.length > VIRTUALIZE_ABOVE;
  useEffect(() => {
    if (!listContainerRef.current) return;
    setViewportH(listContainerRef.current.clientHeight);
    const onResize = () => {
      if (listContainerRef.current) setViewportH(listContainerRef.current.clientHeight);
    };
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  const onListScroll = useCallback((ev: React.UIEvent<HTMLDivElement>) => {
    if (virtualize) setScrollTop(ev.currentTarget.scrollTop);
  }, [virtualize]);

  const totalRows = Math.ceil(results.length / rowsPerCol);
  const totalHeight = totalRows * rowHeight;
  const overscan = 3;
  const startRow = virtualize ? Math.max(0, Math.floor(scrollTop / rowHeight) - overscan) : 0;
  const endRow = virtualize
    ? Math.min(totalRows, Math.ceil((scrollTop + viewportH) / rowHeight) + overscan)
    : totalRows;

  const visibleItems: Array<{ entity: Entity; row: number; col: number; absIdx: number }> = [];
  for (let r = startRow; r < endRow; r++) {
    for (let c = 0; c < rowsPerCol; c++) {
      const idx = r * rowsPerCol + c;
      if (idx >= results.length) break;
      visibleItems.push({ entity: results[idx], row: r, col: c, absIdx: idx });
    }
  }

  // ─── Render ───────────────────────────────────────────────────────────────
  if (!remoteData && dataUrls) {
    return (
      <div
        aria-busy={!loadError}
        style={{
          minHeight: 620,
          display: "grid",
          placeItems: "center",
          borderTop: "1px solid rgba(157,124,244,0.18)",
          background: "linear-gradient(180deg, rgba(12,7,24,0.7), rgba(0,0,5,0.92))",
          padding: 24,
          textAlign: "center",
        }}
      >
        <div>
          <p style={{ fontFamily: "monospace", color: "#b78cff", letterSpacing: "0.14em", textTransform: "uppercase" }}>
            {loadError ? "Catalog unavailable" : "Loading versioned catalog"}
          </p>
          <p style={{ opacity: 0.72 }}>
            {loadError ? loadError : "Preparing filters and relationship previews…"}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="explorer-shell" style={shellStyle}>
      <style>{`
        @media (max-width: 900px) {
          .explorer-shell {
            flex-direction: column;
            height: auto !important;
            min-height: 100vh;
          }
          .explorer-sidebar {
            height: auto !important;
          }
          .explorer-sidebar > aside {
            width: 100% !important;
            max-width: none !important;
            max-height: 44vh !important;
          }
          .explorer-results {
            min-height: 62vh;
            height: 62vh !important;
          }
          .explorer-preview {
            flex: 0 0 auto !important;
            width: 100%;
            max-width: none !important;
            height: auto !important;
            min-height: 320px;
          }
        }
      `}</style>
      {/* Left: filters */}
      <div className="explorer-sidebar" style={{ flex: "0 0 auto", height: "100%", overflow: "hidden" }}>
        <FilterSidebar
          entities={entities}
          filter={filter}
          onChange={setFilter}
          storageKey="hugin.filterSidebar.explore.sectionState"
          showSortControls={false}
        />
      </div>

      {/* Center: results */}
      <div className="explorer-results" style={centerCol}>
        <ExplorerHeader
          count={results.length}
          total={entities.length}
          viewMode={viewMode}
          onViewMode={setViewMode}
          sortBy={filter.sortBy}
          sortDir={filter.sortDir}
          onSort={(sortBy, sortDir) => setFilter((f) => ({ ...f, sortBy, sortDir }))}
        />

        <div
          ref={listContainerRef}
          onScroll={onListScroll}
          style={{ flex: 1, overflowY: "auto", padding: "12px 14px" }}
          role="listbox"
          aria-label="Filtered entities"
        >
          {results.length === 0 && (
            <p style={{ opacity: 0.6, fontStyle: "italic", padding: "24px 4px" }}>
              No entities match the current filters.
            </p>
          )}

          {results.length > 0 && (
            <div style={{ position: "relative", height: virtualize ? totalHeight : "auto" }}>
              {viewMode === "list" ? (
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {visibleItems.map((it) => (
                    <div
                      key={it.entity.id}
                      style={virtualize ? {
                        position: "absolute", top: it.row * rowHeight,
                        left: 0, right: 0, height: rowHeight - 8,
                      } : undefined}
                    >
                      <EntityListCard
                        entity={it.entity}
                        galaxyName={galaxyNameMap.get(it.entity.galaxyId)}
                        selected={it.entity.id === selectedId}
                        variant="list"
                        routePrefix={routePrefix}
                        onSelect={handleCardClick}
                      />
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{
                  display: "grid",
                  gridTemplateColumns: `repeat(${GRID_COLS}, minmax(0, 1fr))`,
                  gap: 10,
                }}>
                  {visibleItems.map((it) => (
                    <div
                      key={it.entity.id}
                      style={virtualize ? {
                        position: "absolute",
                        top: it.row * rowHeight,
                        left: `calc((100% + 10px) * ${it.col / GRID_COLS})`,
                        width: `calc((100% - ${(GRID_COLS - 1) * 10}px) / ${GRID_COLS})`,
                        height: rowHeight - 10,
                      } : undefined}
                    >
                      <EntityListCard
                        entity={it.entity}
                        galaxyName={galaxyNameMap.get(it.entity.galaxyId)}
                        selected={it.entity.id === selectedId}
                        variant="grid"
                        routePrefix={routePrefix}
                        onSelect={handleCardClick}
                      />
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Right: preview */}
      <div className="explorer-preview" style={rightCol}>
        <EntityPreviewPane
          entity={selectedEntity}
          entitiesById={entitiesById}
          relations={relations}
          galaxyName={selectedEntity ? galaxyNameMap.get(selectedEntity.galaxyId) : undefined}
          routePrefix={routePrefix}
          onSelectEntity={setSelectedId}
        />
      </div>
    </div>
  );
}

// ─── Header (results, view toggle, sort) ─────────────────────────────────────
function ExplorerHeader({
  count, total, viewMode, onViewMode, sortBy, sortDir, onSort,
}: {
  count: number; total: number;
  viewMode: "grid" | "list"; onViewMode: (v: "grid" | "list") => void;
  sortBy: SortBy; sortDir: SortDir;
  onSort: (sortBy: SortBy, sortDir: SortDir) => void;
}) {
  return (
    <div style={headerBar}>
      <div style={{ fontFamily: "monospace", fontSize: 12, color: "#c8d4e8" }}>
        <strong style={{ color: "var(--nav-accent)" }}>{count.toLocaleString()}</strong> / {total.toLocaleString()} entities
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <label style={{ fontSize: 10, color: "#94a3b8", fontFamily: "monospace" }}>SORT</label>
        <select
          value={sortBy}
          onChange={(ev) => onSort(ev.target.value as SortBy, sortDir)}
          style={selectStyle}
          aria-label="Sort by"
        >
          <option value="connections">Connections</option>
          <option value="mass">Mass</option>
          <option value="recent">Recent</option>
          <option value="alpha">Alphabetical</option>
        </select>
        <button
          type="button"
          onClick={() => onSort(sortBy, sortDir === "asc" ? "desc" : "asc")}
          style={iconBtn}
          aria-label={sortDir === "desc" ? "Descending" : "Ascending"}
          title={sortDir === "desc" ? "Descending" : "Ascending"}
        >
          {sortDir === "desc" ? "↓" : "↑"}
        </button>

        <div style={{ width: 1, height: 20, background: "rgba(255,255,255,0.15)", margin: "0 4px" }} />

        <button
          type="button"
          onClick={() => onViewMode("list")}
          style={viewMode === "list" ? toggleBtnActive : toggleBtn}
          aria-pressed={viewMode === "list"}
          title="List view"
        >☰ List</button>
        <button
          type="button"
          onClick={() => onViewMode("grid")}
          style={viewMode === "grid" ? toggleBtnActive : toggleBtn}
          aria-pressed={viewMode === "grid"}
          title="Grid view"
        >▦ Grid</button>
      </div>
    </div>
  );
}

// ─── Styles ──────────────────────────────────────────────────────────────────
const shellStyle: CSSProperties = {
  display: "flex",
  width: "100%",
  height: "calc(100vh - var(--header, 68px) - 8px)",
  minHeight: 500,
  background: "rgba(0,4,12,0.4)",
  border: "1px solid rgba(157,124,244,0.08)",
};

const centerCol: CSSProperties = {
  flex: 1,
  minWidth: 0,
  display: "flex",
  flexDirection: "column",
  height: "100%",
  overflow: "hidden",
  borderLeft: "1px solid rgba(255,255,255,0.06)",
};

const rightCol: CSSProperties = {
  flex: "0 0 360px",
  maxWidth: "40vw",
  height: "100%",
  overflow: "hidden",
};

const headerBar: CSSProperties = {
  display: "flex", alignItems: "center", justifyContent: "space-between",
  gap: 12,
  padding: "8px 14px",
  borderBottom: "1px solid rgba(157,124,244,0.15)",
  background: "rgba(0,8,20,0.6)",
  flex: "0 0 auto",
};

const selectStyle: CSSProperties = {
  background: "rgba(0,0,0,0.45)",
  color: "#e8f0ff",
  border: "1px solid rgba(255,255,255,0.15)",
  fontFamily: "monospace",
  fontSize: 11,
  padding: "3px 6px",
  minHeight: 28,
};

const iconBtn: CSSProperties = {
  background: "rgba(0,0,0,0.35)",
  color: "var(--nav-accent)",
  border: "1px solid rgba(157,124,244,0.28)",
  fontFamily: "monospace",
  fontSize: 12,
  padding: "3px 8px",
  minHeight: 28,
  cursor: "pointer",
};

const toggleBtn: CSSProperties = {
  background: "rgba(0,0,0,0.35)",
  color: "#c8d4e8",
  border: "1px solid rgba(255,255,255,0.15)",
  fontFamily: "monospace",
  fontSize: 11,
  padding: "3px 8px",
  minHeight: 28,
  cursor: "pointer",
};
const toggleBtnActive: CSSProperties = {
  ...toggleBtn,
  background: "rgba(157,124,244,0.2)",
  borderColor: "var(--nav-accent)",
  color: "var(--nav-accent)",
  fontWeight: 700,
};
