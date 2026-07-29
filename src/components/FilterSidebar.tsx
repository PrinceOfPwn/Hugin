import { useEffect, useMemo, useRef, useState } from "react";
import type { Entity } from "../lib/types";
import { EMPTY_FILTER, type FilterState, type SortBy, type Tier, type TriState } from "../lib/filters";
import { MITRE_TACTICS } from "../lib/mitre-tactics";

// ─── Types ───────────────────────────────────────────────────────────────────
interface Props {
  entities: Entity[];
  filter: FilterState;
  onChange: (next: FilterState) => void;
  storageKey?: string; // for section-collapse persistence
  showSortControls?: boolean; // Off by default — ExplorerShell renders sort in the header instead.
}

type SectionId =
  | "search" | "time" | "tactic" | "galaxies" | "tiers" | "kinds"
  | "categories" | "tags" | "mitre" | "connections" | "recent"
  | "hasCode" | "hasWalkthrough" | "mass" | "sort";

const DEFAULT_SECTIONS: Record<SectionId, boolean> = {
  search: true,
  time: true,
  tactic: false,
  galaxies: true,
  tiers: true,
  kinds: true,
  categories: false,
  tags: false,
  mitre: false,
  connections: false,
  recent: false,
  hasCode: false,
  hasWalkthrough: false,
  mass: false,
  sort: false,
};

const MITRE_RE = /^T\d{4}(?:\.\d+)?$/;

// ─── Small helpers ───────────────────────────────────────────────────────────
function toggle<T>(set: Set<T>, val: T): Set<T> {
  const s = new Set(set);
  if (s.has(val)) s.delete(val); else s.add(val);
  return s;
}
function countBy<T>(items: T[], keyFn: (t: T) => string | undefined | null): Map<string, number> {
  const m = new Map<string, number>();
  for (const it of items) {
    const k = keyFn(it);
    if (!k) continue;
    m.set(k, (m.get(k) || 0) + 1);
  }
  return m;
}
function sortedByCount(m: Map<string, number>): Array<[string, number]> {
  return [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

// ─── Section wrapper ─────────────────────────────────────────────────────────
function Section({
  id, title, open, onToggle, children,
}: { id: SectionId; title: string; open: boolean; onToggle: () => void; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 12, borderBottom: "1px solid rgba(255,255,255,0.06)", paddingBottom: 10 }}>
      <button
        onClick={onToggle}
        aria-expanded={open}
        style={{
          background: "transparent", border: "none", color: "var(--nav-accent)",
          fontFamily: "monospace", fontSize: 10, cursor: "pointer",
          textTransform: "uppercase", letterSpacing: "0.14em",
          padding: "2px 0 6px", width: "100%", textAlign: "left",
          display: "flex", justifyContent: "space-between", alignItems: "center",
        }}
      >
        <span>{open ? "▾" : "▸"} {title}</span>
      </button>
      {open && <div>{children}</div>}
    </div>
  );
}

// ─── Debounced input ─────────────────────────────────────────────────────────
function useDebouncedCallback<T extends (...a: any[]) => void>(cb: T, delay: number) {
  const cbRef = useRef(cb);
  cbRef.current = cb;
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  return (...args: Parameters<T>) => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => cbRef.current(...args), delay);
  };
}

// ─── Main ────────────────────────────────────────────────────────────────────
export default function FilterSidebar({ entities, filter, onChange, storageKey = "hugin.filterSidebar.sectionState", showSortControls = false }: Props) {
  // Section open/collapsed state.
  const [sections, setSections] = useState<Record<SectionId, boolean>>(() => {
    if (typeof window === "undefined") return DEFAULT_SECTIONS;
    try {
      const raw = window.localStorage.getItem(storageKey);
      if (raw) return { ...DEFAULT_SECTIONS, ...JSON.parse(raw) };
    } catch { /* noop */ }
    return DEFAULT_SECTIONS;
  });
  useEffect(() => {
    if (typeof window === "undefined") return;
    try { window.localStorage.setItem(storageKey, JSON.stringify(sections)); } catch { /* noop */ }
  }, [sections, storageKey]);

  const toggleSection = (id: SectionId) => setSections((s) => ({ ...s, [id]: !s[id] }));

  // Aggregations for facets.
  const facets = useMemo(() => {
    const galaxies = sortedByCount(countBy(entities, (e) => e.galaxyId));
    const kinds = sortedByCount(countBy(entities, (e) => e.kind));
    const categories = sortedByCount(countBy(entities, (e) => e.category));
    const tagCounts = new Map<string, number>();
    const mitreCounts = new Map<string, number>();
    for (const e of entities) {
      for (const t of e.tags || []) {
        if (MITRE_RE.test(t)) mitreCounts.set(t, (mitreCounts.get(t) || 0) + 1);
        else tagCounts.set(t, (tagCounts.get(t) || 0) + 1);
      }
    }
    return {
      galaxies,
      kinds,
      categories,
      tags: sortedByCount(tagCounts),
      mitre: sortedByCount(mitreCounts),
    };
  }, [entities]);

  // ─── Search (debounced) ───────────────────────────────────────────────────
  const [queryDraft, setQueryDraft] = useState(filter.query);
  useEffect(() => setQueryDraft(filter.query), [filter.query]);
  const commitQuery = useDebouncedCallback((v: string) => {
    onChange({ ...filter, query: v });
  }, 200);

  // ─── Typeahead state for tags and mitre ───────────────────────────────────
  const [tagInput, setTagInput] = useState("");
  const [mitreInput, setMitreInput] = useState("");
  const [galaxiesExpanded, setGalaxiesExpanded] = useState(false);

  const tagSuggestions = useMemo(() => {
    const q = tagInput.trim().toLowerCase();
    if (!q) return [] as Array<[string, number]>;
    return facets.tags.filter(([t]) => t.toLowerCase().includes(q)).slice(0, 12);
  }, [facets.tags, tagInput]);
  const mitreSuggestions = useMemo(() => {
    const q = mitreInput.trim().toLowerCase();
    if (!q) return [] as Array<[string, number]>;
    return facets.mitre.filter(([t]) => t.toLowerCase().includes(q)).slice(0, 12);
  }, [facets.mitre, mitreInput]);

  // ─── Clear all ────────────────────────────────────────────────────────────
  const clearAll = () => onChange({ ...EMPTY_FILTER });

  // Precompute connections range from data for slider bounds.
  const connectionBounds = useMemo(() => {
    let max = 0;
    for (const e of entities) if ((e.degree ?? 0) > max) max = e.degree || 0;
    return { min: 0, max: Math.max(max, 1) };
  }, [entities]);

  // ─── Render ───────────────────────────────────────────────────────────────
  const galaxyRows = galaxiesExpanded ? facets.galaxies : facets.galaxies.slice(0, 12);
  const tierList: Tier[] = ["S", "A", "B", "C"];

  return (
    <aside style={{
      width: 320, maxWidth: "90vw", height: "100%",
      maxHeight: "calc(100vh - 96px)",
      background: "linear-gradient(180deg, rgba(0,8,20,0.92), rgba(0,4,12,0.85))",
      borderRight: "1px solid rgba(157,124,244,0.15)", backdropFilter: "blur(8px)",
      fontFamily: "'Fira Code', ui-monospace, monospace", fontSize: 12,
      color: "#dae4f0", padding: "16px 14px", overflowY: "auto",
      boxSizing: "border-box",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 12 }}>
        <div style={{ fontSize: 10, opacity: 0.65, letterSpacing: "0.14em", textTransform: "uppercase", color: "var(--nav-accent)" }}>Filters</div>
        <button onClick={clearAll} style={{
          background: "transparent", border: "1px solid rgba(255,255,255,0.15)", color: "#c8d4e8",
          fontFamily: "monospace", fontSize: 10, padding: "2px 8px", cursor: "pointer",
          textTransform: "uppercase", letterSpacing: "0.1em",
        }}>Clear all</button>
      </div>

      {/* Search */}
      <Section id="search" title="Search" open={sections.search} onToggle={() => toggleSection("search")}>
        <input
          aria-label="Search catalog"
          value={queryDraft}
          onChange={(e) => { setQueryDraft(e.target.value); commitQuery(e.target.value); }}
          placeholder="title, summary, tags…"
          style={inputStyle}
        />
        <div style={{ display: "flex", gap: 4, marginTop: 6 }}>
          {(["titleSummary", "full"] as const).map((scope) => (
            <button
              key={scope}
              onClick={() => onChange({ ...filter, searchScope: scope })}
              style={filter.searchScope === scope ? chipStyleActive : chipStyle}
              type="button"
            >
              {scope === "titleSummary" ? "Title + summary" : "Full"}
            </button>
          ))}
        </div>
      </Section>

      {/* Time window */}
      <Section id="time" title="Time window" open={sections.time} onToggle={() => toggleSection("time")}>
        {(["7d", "30d", "90d", "all"] as const).map((w) => (
          <label key={w} style={rowStyle}>
            <input
              type="radio"
              name="timeWindow"
              checked={filter.timeWindow === w}
              onChange={() => onChange({ ...filter, timeWindow: w })}
            />
            <span>{w === "all" ? "All time" : `Last ${w}`}</span>
          </label>
        ))}
      </Section>

      {/* MITRE tactic (kill-chain phase) */}
      <Section id="tactic" title={`MITRE tactic${filter.mitreTactic.size ? ` · ${filter.mitreTactic.size}` : ""}`} open={sections.tactic} onToggle={() => toggleSection("tactic")}>
        {MITRE_TACTICS.map((t) => (
          <label key={t.id} style={rowStyle} title={t.name}>
            <input
              type="checkbox"
              checked={filter.mitreTactic.has(t.id)}
              onChange={() => onChange({ ...filter, mitreTactic: toggle(filter.mitreTactic, t.id) })}
            />
            <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{t.name}</span>
            <span style={countStyle}>{t.id.replace("TA", "")}</span>
          </label>
        ))}
      </Section>

      {/* Galaxies */}
      <Section id="galaxies" title={`Galaxies${filter.galaxies.size ? ` · ${filter.galaxies.size}` : ""}`} open={sections.galaxies} onToggle={() => toggleSection("galaxies")}>
        {galaxyRows.map(([g, n]) => (
          <label key={g} style={rowStyle} title={g}>
            <input
              type="checkbox"
              checked={filter.galaxies.has(g)}
              onChange={() => onChange({ ...filter, galaxies: toggle(filter.galaxies, g) })}
            />
            <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{g}</span>
            <span style={countStyle}>{n}</span>
          </label>
        ))}
        {facets.galaxies.length > 12 && (
          <button onClick={() => setGalaxiesExpanded((v) => !v)} style={linkBtn}>
            {galaxiesExpanded ? "Show fewer" : `Show all ${facets.galaxies.length}`}
          </button>
        )}
      </Section>

      {/* Tiers */}
      <Section id="tiers" title={`Tiers${filter.tiers.size ? ` · ${filter.tiers.size}` : ""}`} open={sections.tiers} onToggle={() => toggleSection("tiers")}>
        {tierList.map((t) => (
          <label key={t} style={rowStyle}>
            <input
              type="checkbox"
              checked={filter.tiers.has(t)}
              onChange={() => onChange({ ...filter, tiers: toggle(filter.tiers, t) })}
            />
            <span>Tier {t}</span>
          </label>
        ))}
      </Section>

      {/* Kinds */}
      <Section id="kinds" title={`Kinds${filter.kinds.size ? ` · ${filter.kinds.size}` : ""}`} open={sections.kinds} onToggle={() => toggleSection("kinds")}>
        {facets.kinds.map(([k, n]) => (
          <label key={k} style={rowStyle} title={k}>
            <input
              type="checkbox"
              checked={filter.kinds.has(k)}
              onChange={() => onChange({ ...filter, kinds: toggle(filter.kinds, k) })}
            />
            <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{k}</span>
            <span style={countStyle}>{n}</span>
          </label>
        ))}
      </Section>

      {/* Categories */}
      <Section id="categories" title={`Categories${filter.categories.size ? ` · ${filter.categories.size}` : ""}`} open={sections.categories} onToggle={() => toggleSection("categories")}>
        {facets.categories.map(([c, n]) => (
          <label key={c} style={rowStyle} title={c}>
            <input
              type="checkbox"
              checked={filter.categories.has(c)}
              onChange={() => onChange({ ...filter, categories: toggle(filter.categories, c) })}
            />
            <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{c}</span>
            <span style={countStyle}>{n}</span>
          </label>
        ))}
      </Section>

      {/* Tags typeahead */}
      <Section id="tags" title={`Tags${filter.tags.size ? ` · ${filter.tags.size}` : ""}`} open={sections.tags} onToggle={() => toggleSection("tags")}>
        <input
          value={tagInput}
          onChange={(e) => setTagInput(e.target.value)}
          placeholder="Type to search tags…"
          style={inputStyle}
        />
        {filter.tags.size > 0 && (
          <div style={chipRow}>
            {[...filter.tags].slice(0, 20).map((t) => (
              <button key={t} onClick={() => onChange({ ...filter, tags: toggle(filter.tags, t) })} style={chipStyle}>
                {t} ×
              </button>
            ))}
            {filter.tags.size > 20 && <span style={{ fontSize: 10, opacity: 0.5 }}>+{filter.tags.size - 20}</span>}
          </div>
        )}
        {tagSuggestions.length > 0 && (
          <div style={{ marginTop: 6 }}>
            {tagSuggestions.map(([t, n]) => (
              <label key={t} style={rowStyle} title={t}>
                <input
                  type="checkbox"
                  checked={filter.tags.has(t)}
                  onChange={() => onChange({ ...filter, tags: toggle(filter.tags, t) })}
                />
                <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{t}</span>
                <span style={countStyle}>{n}</span>
              </label>
            ))}
          </div>
        )}
      </Section>

      {/* MITRE typeahead */}
      <Section id="mitre" title={`MITRE${filter.mitre.size ? ` · ${filter.mitre.size}` : ""}`} open={sections.mitre} onToggle={() => toggleSection("mitre")}>
        <input
          value={mitreInput}
          onChange={(e) => setMitreInput(e.target.value)}
          placeholder="T1055, T1027…"
          style={inputStyle}
        />
        {filter.mitre.size > 0 && (
          <div style={chipRow}>
            {[...filter.mitre].slice(0, 20).map((t) => (
              <button key={t} onClick={() => onChange({ ...filter, mitre: toggle(filter.mitre, t) })} style={chipStyle}>
                {t} ×
              </button>
            ))}
          </div>
        )}
        {mitreSuggestions.length > 0 && (
          <div style={{ marginTop: 6 }}>
            {mitreSuggestions.map(([t, n]) => (
              <label key={t} style={rowStyle}>
                <input
                  type="checkbox"
                  checked={filter.mitre.has(t)}
                  onChange={() => onChange({ ...filter, mitre: toggle(filter.mitre, t) })}
                />
                <span style={{ flex: 1 }}>{t}</span>
                <span style={countStyle}>{n}</span>
              </label>
            ))}
          </div>
        )}
      </Section>

      {/* Connections range */}
      <Section
        id="connections"
        title={`Connections${filter.connectionsMin || filter.connectionsMax ? ` · ${filter.connectionsMin || 0}–${filter.connectionsMax || connectionBounds.max}` : ""}`}
        open={sections.connections}
        onToggle={() => toggleSection("connections")}
      >
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11 }}>
            <span style={{ width: 32, opacity: 0.6 }}>Min</span>
            <input
              type="range"
              min={0} max={connectionBounds.max} step={1}
              value={filter.connectionsMin}
              onChange={(e) => onChange({ ...filter, connectionsMin: Number(e.target.value) })}
              style={{ flex: 1 }}
            />
            <span style={{ minWidth: 28, textAlign: "right", fontVariantNumeric: "tabular-nums" }}>{filter.connectionsMin}</span>
          </label>
          <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11 }}>
            <span style={{ width: 32, opacity: 0.6 }}>Max</span>
            <input
              type="range"
              min={0} max={connectionBounds.max} step={1}
              value={filter.connectionsMax}
              onChange={(e) => onChange({ ...filter, connectionsMax: Number(e.target.value) })}
              style={{ flex: 1 }}
            />
            <span style={{ minWidth: 28, textAlign: "right", fontVariantNumeric: "tabular-nums" }}>
              {filter.connectionsMax || "∞"}
            </span>
          </label>
        </div>
      </Section>

      {/* Recent activity */}
      <Section
        id="recent"
        title={`Recent activity${filter.recentActivityDays != null ? ` · ${filter.recentActivityDays}d` : ""}`}
        open={sections.recent}
        onToggle={() => toggleSection("recent")}
      >
        <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
          {[null, 7, 30, 90].map((d) => {
            const active = filter.recentActivityDays === d;
            return (
              <button
                key={String(d)}
                type="button"
                onClick={() => onChange({ ...filter, recentActivityDays: d })}
                style={active ? chipStyleActive : chipStyle}
              >
                {d == null ? "Any" : `${d}d`}
              </button>
            );
          })}
        </div>
      </Section>

      {/* Has code */}
      <Section id="hasCode" title={`Has code${filter.hasCode !== "any" ? ` · ${filter.hasCode}` : ""}`} open={sections.hasCode} onToggle={() => toggleSection("hasCode")}>
        <TriRow value={filter.hasCode} onChange={(v) => onChange({ ...filter, hasCode: v })} />
      </Section>

      {/* Has walkthrough */}
      <Section id="hasWalkthrough" title={`Has walkthrough${filter.hasWalkthrough !== "any" ? ` · ${filter.hasWalkthrough}` : ""}`} open={sections.hasWalkthrough} onToggle={() => toggleSection("hasWalkthrough")}>
        <TriRow value={filter.hasWalkthrough} onChange={(v) => onChange({ ...filter, hasWalkthrough: v })} />
      </Section>

      {/* Mass min */}
      <Section id="mass" title={`Mass min${filter.massMin > 0 ? ` · ≥ ${filter.massMin}` : ""}`} open={sections.mass} onToggle={() => toggleSection("mass")}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <input
            type="range"
            min={0} max={20} step={0.5}
            value={filter.massMin}
            onChange={(e) => onChange({ ...filter, massMin: Number(e.target.value) })}
            style={{ flex: 1 }}
          />
          <span style={{ fontSize: 11, fontVariantNumeric: "tabular-nums", minWidth: 32, textAlign: "right" }}>
            {filter.massMin.toFixed(1)}
          </span>
        </div>
      </Section>

      {/* Sort by */}
      {showSortControls && (
        <Section id="sort" title={`Sort · ${filter.sortBy} ${filter.sortDir}`} open={sections.sort} onToggle={() => toggleSection("sort")}>
          <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
            {(["mass", "connections", "recent", "alpha"] as SortBy[]).map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => onChange({ ...filter, sortBy: s })}
                style={filter.sortBy === s ? chipStyleActive : chipStyle}
              >
                {s}
              </button>
            ))}
          </div>
          <div style={{ display: "flex", gap: 4, marginTop: 6 }}>
            {(["desc", "asc"] as const).map((d) => (
              <button
                key={d}
                type="button"
                onClick={() => onChange({ ...filter, sortDir: d })}
                style={filter.sortDir === d ? chipStyleActive : chipStyle}
              >
                {d === "desc" ? "↓ desc" : "↑ asc"}
              </button>
            ))}
          </div>
        </Section>
      )}
    </aside>
  );
}

// ─── Tri-state radio row (any / yes / no) ────────────────────────────────────
function TriRow({ value, onChange }: { value: TriState; onChange: (v: TriState) => void }) {
  const opts: TriState[] = ["any", "yes", "no"];
  return (
    <div style={{ display: "flex", gap: 4 }}>
      {opts.map((v) => (
        <button
          key={v}
          type="button"
          onClick={() => onChange(v)}
          style={value === v ? chipStyleActive : chipStyle}
        >
          {v}
        </button>
      ))}
    </div>
  );
}

// ─── Styles ──────────────────────────────────────────────────────────────────
const rowStyle: React.CSSProperties = {
  display: "flex", alignItems: "center", gap: 8,
  padding: "3px 2px", fontSize: 11, cursor: "pointer",
};
const countStyle: React.CSSProperties = {
  fontSize: 10, opacity: 0.5, fontVariantNumeric: "tabular-nums",
};
const inputStyle: React.CSSProperties = {
  width: "100%", boxSizing: "border-box", background: "rgba(0,0,0,0.35)",
  color: "#e8f0ff", border: "1px solid rgba(255,255,255,0.12)",
  padding: "6px 8px", fontFamily: "monospace", fontSize: 11, outline: "none",
};
const chipRow: React.CSSProperties = {
  display: "flex", flexWrap: "wrap", gap: 4, marginTop: 6,
};
const chipStyle: React.CSSProperties = {
  background: "rgba(157,124,244,0.15)", color: "var(--nav-accent)",
  border: "1px solid rgba(157,124,244,0.35)", padding: "2px 6px",
  fontFamily: "monospace", fontSize: 10, cursor: "pointer",
};
const chipStyleActive: React.CSSProperties = {
  background: "rgba(157,124,244,0.55)", color: "#001018",
  border: "1px solid var(--nav-accent)", padding: "2px 6px",
  fontFamily: "monospace", fontSize: 10, cursor: "pointer",
  fontWeight: 700,
};
const linkBtn: React.CSSProperties = {
  background: "transparent", border: "none", color: "var(--nav-accent)",
  fontFamily: "monospace", fontSize: 10, cursor: "pointer",
  padding: "4px 0", textDecoration: "underline",
};
