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

  const results = useMemo(() => {
    const filtered = filterEntities(entities, filter);
    return filtered
      .slice()
      .sort((a, b) => tsOf(b) - tsOf(a))
      .slice(0, 50);
  }, [entities, filter]);

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
          background: "rgba(0,8,20,0.55)", border: "1px solid rgba(0,240,255,0.18)",
          color: "#c8d4e8", fontFamily: "monospace", fontSize: 12,
        }}>
          <strong style={{ color: "#00f0ff" }}>{stats.total.toLocaleString()}</strong> entities ·{" "}
          <strong style={{ color: "#00f0ff" }}>{stats.n7.toLocaleString()}</strong> new this week ·{" "}
          <strong style={{ color: "#00f0ff" }}>{stats.n30.toLocaleString()}</strong> this month
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
                border: "1px solid rgba(0,240,255,0.14)",
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
                    background: "rgba(0,240,255,0.15)", color: "#00f0ff",
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
  background: "rgba(0,240,255,0.12)", color: "#00f0ff",
  border: "1px solid rgba(0,240,255,0.28)",
};
const badgeMuted: React.CSSProperties = {
  padding: "2px 6px",
  background: "rgba(255,255,255,0.06)", color: "#c8d4e8",
  border: "1px solid rgba(255,255,255,0.12)",
};
