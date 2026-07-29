// ─── Bug fix (2026-07-28) ──────────────────────────────────────────────────
// Symptom: on /latest, toggling any filter caused *different* entries to
// surface — often ones the user had never seen at the top of the page —
// which felt like "the filter isn't filtering, more entries appear."
//
// Root cause: `results` used to run `filterEntities(entities, filter)` FIRST
// and *then* pick the top-50 by recency of the filtered subset. That means
// the pool the top-50 was drawn from changed with the filter — so filtering
// could reveal entries that were not in the original "50 most recently added
// across the graph" pool advertised in the page header. That is the opposite
// of "Narrow with filters below."
//
// Fix: pin the pool to the top-50 by recency of ALL entities first, then run
// `filterEntities` over that fixed pool. Filtering can only ever narrow the
// visible list now — it can never surface entries outside the recent-50.
// The filter engine (`filterEntities`) and the /explore + /graph consumers
// are unchanged. `stats.total` still counts the total filter matches across
// the full dataset (useful context in the header bar).
// ────────────────────────────────────────────────────────────────────────────
import { useEffect, useMemo, useRef, useState } from "react";
import type { Entity, Galaxy } from "../lib/types";
import { decodeFilters, encodeFilters, EMPTY_FILTER, filterEntities, type FilterState } from "../lib/filters";
import FilterSidebar from "./FilterSidebar";

interface Props {
  entities: Entity[];
  galaxies: Galaxy[];
  routePrefix: string; // e.g. "/Hugin"
}

// ─── ES time formatter ("hace 3 días" / "hoy") ──────────────────────────────
function fmtDelta(iso: string | null | undefined): string {
  if (!iso) return "sin fecha";
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "sin fecha";
  const diff = Date.now() - t;
  if (diff < 0) return "en el futuro";
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return "hace segundos";
  const min = Math.floor(sec / 60);
  if (min < 60) return `hace ${min} min`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `hace ${hr}h`;
  const days = Math.floor(hr / 24);
  if (days === 0) return "hoy";
  if (days === 1) return "ayer";
  if (days < 30) return `hace ${days} días`;
  const months = Math.floor(days / 30);
  if (months < 12) return `hace ${months} mes${months === 1 ? "" : "es"}`;
  const years = Math.floor(days / 365);
  return `hace ${years} año${years === 1 ? "" : "s"}`;
}

function tsOf(e: Entity): number {
  return Date.parse(e.firstSeenAt || e.lastUpdatedAt || "") || 0;
}

export default function LatestListShell({ entities, galaxies, routePrefix }: Props) {
  const [filter, setFilter] = useState<FilterState>(() => {
    if (typeof window === "undefined") return EMPTY_FILTER;
    return decodeFilters(window.location.search);
  });

  // URL sync (debounced)
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (typeof window === "undefined") return;
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      const qs = encodeFilters(filter);
      window.history.replaceState(null, "", `${window.location.pathname}${qs}`);
    }, 500);
    return () => { if (timer.current) clearTimeout(timer.current); };
  }, [filter]);

  const galaxyName = useMemo(() => {
    const m = new Map<string, string>();
    for (const g of galaxies) m.set(g.id, g.name);
    return m;
  }, [galaxies]);

  // Pool of "the 50 most recently added entities across the graph"
  // — fixed, filter-independent. Filtering only ever narrows this pool.
  const recentPool = useMemo(() => {
    return entities
      .slice()
      .sort((a, b) => tsOf(b) - tsOf(a))
      .slice(0, 50);
  }, [entities]);

  const results = useMemo(() => {
    // `filterEntities` re-sorts by `filter.sortBy` at the end, which would
    // clobber our recency order — so re-sort by tsOf desc to preserve the
    // "most recently added first" contract of /latest.
    return filterEntities(recentPool, filter)
      .slice()
      .sort((a, b) => tsOf(b) - tsOf(a));
  }, [recentPool, filter]);

  // Stats: total filtered, "new this week" (7d), "this month" (30d)
  const stats = useMemo(() => {
    const now = Date.now();
    const wk = now - 7 * 86400 * 1000;
    const mo = now - 30 * 86400 * 1000;
    let n7 = 0, n30 = 0;
    const filtered = filterEntities(entities, filter);
    for (const e of filtered) {
      const t = tsOf(e);
      if (!t) continue;
      if (t >= wk) n7 += 1;
      if (t >= mo) n30 += 1;
    }
    return { total: filtered.length, n7, n30 };
  }, [entities, filter]);

  return (
    <div style={{ display: "flex", gap: 20, alignItems: "flex-start" }}>
      <div style={{ flex: "0 0 auto", position: "sticky", top: 0, maxHeight: "100vh" }}>
        <FilterSidebar
          entities={entities}
          filter={filter}
          onChange={setFilter}
          storageKey="hugin.filterSidebar.latest.sectionState"
        />
      </div>
      <div style={{ flex: 1, minWidth: 0, padding: "10px 4px" }}>
        <div style={{
          padding: "10px 14px", marginBottom: 16,
          background: "rgba(0,8,20,0.55)", border: "1px solid rgba(157,124,244,0.18)",
          color: "#c8d4e8", fontFamily: "monospace", fontSize: 12,
        }}>
          <strong style={{ color: "var(--nav-accent)" }}>{stats.total.toLocaleString()}</strong> entities ·{" "}
          <strong style={{ color: "var(--nav-accent)" }}>{stats.n7.toLocaleString()}</strong> new this week ·{" "}
          <strong style={{ color: "var(--nav-accent)" }}>{stats.n30.toLocaleString()}</strong> this month
        </div>

        {results.length === 0 && (
          <p style={{ opacity: 0.6, fontStyle: "italic" }}>No entities match the current filters.</p>
        )}

        <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "grid", gap: 10 }}>
          {results.map((e) => {
            const delta = fmtDelta(e.firstSeenAt || e.lastUpdatedAt);
            const summary = (e.summary || "").slice(0, 200);
            const href = `${routePrefix}${e.route}`;
            return (
              <li key={e.id} style={{
                border: "1px solid rgba(157,124,244,0.14)",
                background: "rgba(0,8,20,0.5)",
                padding: "12px 14px",
                borderRadius: 3,
              }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", gap: 12, marginBottom: 6 }}>
                  <a href={href} style={{ color: "#e8f0ff", fontSize: 15, fontWeight: 600, textDecoration: "none" }}>
                    {e.title}
                  </a>
                  <span style={{
                    fontFamily: "monospace", fontSize: 10,
                    background: "rgba(157,124,244,0.15)", color: "var(--nav-accent)",
                    padding: "2px 6px", whiteSpace: "nowrap",
                  }}>{delta}</span>
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 6, fontFamily: "monospace", fontSize: 10 }}>
                  <span style={badge}>{galaxyName.get(e.galaxyId) || e.galaxyId}</span>
                  {e.tier && <span style={badge}>Tier {e.tier}</span>}
                  {e.mass != null && <span style={badge}>mass {e.mass.toFixed(1)}</span>}
                  {e.category && <span style={badgeMuted}>{e.category}</span>}
                </div>
                {summary && (
                  <p style={{ margin: 0, opacity: 0.78, fontSize: 12, lineHeight: 1.5 }}>
                    {summary}{e.summary && e.summary.length > 200 ? "…" : ""}
                  </p>
                )}
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}

const badge: React.CSSProperties = {
  padding: "2px 6px",
  background: "rgba(157,124,244,0.12)", color: "var(--nav-accent)",
  border: "1px solid rgba(157,124,244,0.28)",
};
const badgeMuted: React.CSSProperties = {
  padding: "2px 6px",
  background: "rgba(255,255,255,0.06)", color: "#c8d4e8",
  border: "1px solid rgba(255,255,255,0.12)",
};
