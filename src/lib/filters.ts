// Pure filter engine + URL sync. No React.
import type { Entity } from "./types";
import { tacticsForTags } from "./mitre-tactics";

export type Tier = "S" | "A" | "B" | "C";

export type TriState = "any" | "yes" | "no";
export type SortBy = "mass" | "connections" | "recent" | "alpha";
export type SortDir = "asc" | "desc";
export type SearchScope = "titleSummary" | "full";

export type FilterState = {
  timeWindow: "7d" | "30d" | "90d" | "all";
  galaxies: Set<string>;
  tiers: Set<Tier>;
  kinds: Set<string>;
  tags: Set<string>;
  categories: Set<string>;
  mitre: Set<string>;
  mitreTactic: Set<string>;      // tactic IDs (e.g. "TA0002")
  hasCode: TriState;
  hasWalkthrough: TriState;
  connectionsMin: number;
  connectionsMax: number;         // 0 = "no upper bound"
  recentActivityDays: number | null;
  searchScope: SearchScope;
  sortBy: SortBy;
  sortDir: SortDir;
  massMin: number;
  query: string;
};

export const EMPTY_FILTER: FilterState = {
  timeWindow: "all",
  galaxies: new Set<string>(),
  tiers: new Set<Tier>(),
  kinds: new Set<string>(),
  tags: new Set<string>(),
  categories: new Set<string>(),
  mitre: new Set<string>(),
  mitreTactic: new Set<string>(),
  hasCode: "any",
  hasWalkthrough: "any",
  connectionsMin: 0,
  connectionsMax: 0,
  recentActivityDays: null,
  searchScope: "titleSummary",
  sortBy: "connections",
  sortDir: "desc",
  massMin: 0,
  query: "",
};

const MITRE_RE = /^T\d{4}(?:\.\d+)?$/;
const CODE_TAG_RE = /\b(code|snippet|source[-_]?code)\b/i;
const WALKTHROUGH_TAG_RE = /\b(walkthrough|guide|tutorial|how[-_]?to)\b/i;
const CODE_KINDS = new Set(["source_code", "project_source_code"]);
const WALKTHROUGH_KINDS = new Set(["documentation", "doc", "guide"]);

const WINDOW_MS: Record<FilterState["timeWindow"], number | null> = {
  "7d": 7 * 24 * 3600 * 1000,
  "30d": 30 * 24 * 3600 * 1000,
  "90d": 90 * 24 * 3600 * 1000,
  all: null,
};

function parseTs(s: string | null | undefined): number | null {
  if (!s) return null;
  const n = Date.parse(s);
  return Number.isFinite(n) ? n : null;
}

function entityHasCode(e: Entity): boolean {
  if (CODE_KINDS.has(e.kind)) return true;
  for (const t of e.tags || []) if (CODE_TAG_RE.test(t)) return true;
  return false;
}

function entityHasWalkthrough(e: Entity): boolean {
  const kindOk = WALKTHROUGH_KINDS.has(e.kind);
  for (const t of e.tags || []) {
    if (WALKTHROUGH_TAG_RE.test(t)) return kindOk || true; // walkthrough tag alone qualifies
  }
  return false;
}

function sortComparator(state: FilterState): (a: Entity, b: Entity) => number {
  const dir = state.sortDir === "asc" ? 1 : -1;
  switch (state.sortBy) {
    case "mass":
      return (a, b) => {
        const av = a.mass ?? 0;
        const bv = b.mass ?? 0;
        if (av === bv) return a.title.localeCompare(b.title);
        return (av - bv) * dir;
      };
    case "connections":
      return (a, b) => {
        const av = a.degree ?? 0;
        const bv = b.degree ?? 0;
        if (av === bv) return a.title.localeCompare(b.title);
        return (av - bv) * dir;
      };
    case "recent":
      return (a, b) => {
        const av = parseTs(a.lastUpdatedAt) ?? parseTs(a.firstSeenAt) ?? -Infinity;
        const bv = parseTs(b.lastUpdatedAt) ?? parseTs(b.firstSeenAt) ?? -Infinity;
        if (av === bv) return a.title.localeCompare(b.title);
        return (av - bv) * dir;
      };
    case "alpha":
    default:
      return (a, b) => a.title.localeCompare(b.title) * dir;
  }
}

export function filterEntities(entities: Entity[], state: FilterState): Entity[] {
  const q = state.query.trim().toLowerCase();
  const winMs = WINDOW_MS[state.timeWindow];
  const now = Date.now();
  const cutoff = winMs != null ? now - winMs : null;
  const recentCutoff = state.recentActivityDays != null
    ? now - state.recentActivityDays * 86400 * 1000
    : null;

  const hasGalaxies = state.galaxies.size > 0;
  const hasTiers = state.tiers.size > 0;
  const hasKinds = state.kinds.size > 0;
  const hasTags = state.tags.size > 0;
  const hasCats = state.categories.size > 0;
  const hasMitre = state.mitre.size > 0;
  const hasTactic = state.mitreTactic.size > 0;
  const connMin = state.connectionsMin || 0;
  const connMax = state.connectionsMax || 0;

  const out: Entity[] = [];
  for (const e of entities) {
    // Cheapest checks first.
    if (hasGalaxies && !state.galaxies.has(e.galaxyId)) continue;
    if (hasKinds && !state.kinds.has(e.kind)) continue;
    if (hasCats && !state.categories.has(e.category)) continue;
    if (hasTiers) {
      const t = (e.tier ?? "") as Tier;
      if (!state.tiers.has(t)) continue;
    }
    if (state.massMin > 0) {
      if (e.mass != null && e.mass < state.massMin) continue;
    }
    if (cutoff != null) {
      const ts = parseTs(e.firstSeenAt) ?? parseTs(e.lastUpdatedAt);
      if (ts != null && ts < cutoff) continue;
    }
    if (recentCutoff != null) {
      const ts = parseTs(e.lastUpdatedAt) ?? parseTs(e.firstSeenAt);
      // Recent-activity filter is strict: if there's no timestamp, drop.
      if (ts == null || ts < recentCutoff) continue;
    }
    const deg = e.degree ?? 0;
    if (connMin > 0 && deg < connMin) continue;
    if (connMax > 0 && deg > connMax) continue;

    if (hasTags) {
      const tags = e.tags || [];
      let ok = false;
      for (const t of tags) if (state.tags.has(t)) { ok = true; break; }
      if (!ok) continue;
    }
    if (hasMitre) {
      const tags = e.tags || [];
      let ok = false;
      for (const t of tags) {
        if (MITRE_RE.test(t) && state.mitre.has(t)) { ok = true; break; }
      }
      if (!ok) continue;
    }
    if (hasTactic) {
      const entTactics = tacticsForTags(e.tags || []);
      let ok = false;
      for (const t of state.mitreTactic) if (entTactics.has(t)) { ok = true; break; }
      if (!ok) continue;
    }
    if (state.hasCode !== "any") {
      const has = entityHasCode(e);
      if (state.hasCode === "yes" && !has) continue;
      if (state.hasCode === "no" && has) continue;
    }
    if (state.hasWalkthrough !== "any") {
      const has = entityHasWalkthrough(e);
      if (state.hasWalkthrough === "yes" && !has) continue;
      if (state.hasWalkthrough === "no" && has) continue;
    }
    if (q) {
      // We only carry title/summary/tags client-side. "full" scope adds
      // category + mitre + kind — a reasonable superset when body isn't loaded.
      const parts = [e.title, e.summary, (e.tags || []).join(" ")];
      if (state.searchScope === "full") {
        parts.push(e.category || "", (e.mitre || []).join(" "), e.kind || "");
      }
      const hay = parts.join(" ").toLowerCase();
      if (!hay.includes(q)) continue;
    }
    out.push(e);
  }
  out.sort(sortComparator(state));
  return out;
}

export function summarizeFilters(state: FilterState): string {
  const bits: string[] = [];
  if (state.galaxies.size) bits.push(`${state.galaxies.size} galax${state.galaxies.size === 1 ? "y" : "ies"}`);
  if (state.tiers.size) bits.push(`${state.tiers.size} tier${state.tiers.size === 1 ? "" : "s"}`);
  if (state.kinds.size) bits.push(`${state.kinds.size} kind${state.kinds.size === 1 ? "" : "s"}`);
  if (state.categories.size) bits.push(`${state.categories.size} cat${state.categories.size === 1 ? "" : "s"}`);
  if (state.tags.size) bits.push(`${state.tags.size} tag${state.tags.size === 1 ? "" : "s"}`);
  if (state.mitre.size) bits.push(`${state.mitre.size} mitre`);
  if (state.mitreTactic.size) bits.push(`${state.mitreTactic.size} tactic${state.mitreTactic.size === 1 ? "" : "s"}`);
  if (state.massMin > 0) bits.push(`mass ≥ ${state.massMin}`);
  if (state.connectionsMin > 0) bits.push(`conn ≥ ${state.connectionsMin}`);
  if (state.connectionsMax > 0) bits.push(`conn ≤ ${state.connectionsMax}`);
  if (state.recentActivityDays != null) bits.push(`activity ${state.recentActivityDays}d`);
  if (state.hasCode !== "any") bits.push(`code:${state.hasCode}`);
  if (state.hasWalkthrough !== "any") bits.push(`walkthrough:${state.hasWalkthrough}`);
  if (state.timeWindow !== "all") bits.push(`last ${state.timeWindow}`);
  if (state.query) bits.push(`"${state.query}"`);
  return bits.length ? bits.join(" · ") : "no filters";
}

// ─── URL sync ────────────────────────────────────────────────────────────────
function setStr(s: Set<string>): string { return [...s].join(","); }
function toSet<T extends string>(v: string | null): Set<T> {
  if (!v) return new Set();
  return new Set(v.split(",").map((x) => x.trim()).filter(Boolean) as T[]);
}

const VALID_TRI: TriState[] = ["any", "yes", "no"];
const VALID_SORT_BY: SortBy[] = ["mass", "connections", "recent", "alpha"];
const VALID_SORT_DIR: SortDir[] = ["asc", "desc"];
const VALID_SCOPE: SearchScope[] = ["titleSummary", "full"];

export function encodeFilters(state: FilterState): string {
  const p = new URLSearchParams();
  if (state.timeWindow !== "all") p.set("t", state.timeWindow);
  if (state.galaxies.size) p.set("g", setStr(state.galaxies));
  if (state.tiers.size) p.set("tier", setStr(state.tiers));
  if (state.kinds.size) p.set("k", setStr(state.kinds));
  if (state.tags.size) p.set("tag", setStr(state.tags));
  if (state.categories.size) p.set("cat", setStr(state.categories));
  if (state.mitre.size) p.set("mitre", setStr(state.mitre));
  if (state.massMin > 0) p.set("mass", String(state.massMin));
  if (state.query) p.set("q", state.query);
  // New keys — only serialized when non-default.
  if (state.mitreTactic.size) p.set("mt", setStr(state.mitreTactic));
  if (state.hasCode !== "any") p.set("hc", state.hasCode);
  if (state.hasWalkthrough !== "any") p.set("hw", state.hasWalkthrough);
  if (state.connectionsMin > 0) p.set("cmin", String(state.connectionsMin));
  if (state.connectionsMax > 0) p.set("cmax", String(state.connectionsMax));
  if (state.recentActivityDays != null) p.set("ra", String(state.recentActivityDays));
  if (state.searchScope !== "titleSummary") p.set("ss", state.searchScope);
  if (state.sortBy !== "connections") p.set("sort", state.sortBy);
  if (state.sortDir !== "desc") p.set("dir", state.sortDir);
  const s = p.toString();
  return s ? `?${s}` : "";
}

export function decodeFilters(qs: string): FilterState {
  const p = new URLSearchParams(qs.startsWith("?") ? qs.slice(1) : qs);
  const tw = (p.get("t") || "all") as FilterState["timeWindow"];
  const validTw: FilterState["timeWindow"][] = ["7d", "30d", "90d", "all"];
  const mass = Number(p.get("mass") || "0");
  const cmin = Number(p.get("cmin") || "0");
  const cmax = Number(p.get("cmax") || "0");
  const raRaw = p.get("ra");
  const ra = raRaw != null ? Number(raRaw) : null;
  const hc = (p.get("hc") || "any") as TriState;
  const hw = (p.get("hw") || "any") as TriState;
  const scope = (p.get("ss") || "titleSummary") as SearchScope;
  const sortBy = (p.get("sort") || "connections") as SortBy;
  const sortDir = (p.get("dir") || "desc") as SortDir;
  return {
    timeWindow: validTw.includes(tw) ? tw : "all",
    galaxies: toSet(p.get("g")),
    tiers: toSet<Tier>(p.get("tier")),
    kinds: toSet(p.get("k")),
    tags: toSet(p.get("tag")),
    categories: toSet(p.get("cat")),
    mitre: toSet(p.get("mitre")),
    mitreTactic: toSet(p.get("mt")),
    hasCode: VALID_TRI.includes(hc) ? hc : "any",
    hasWalkthrough: VALID_TRI.includes(hw) ? hw : "any",
    connectionsMin: Number.isFinite(cmin) && cmin > 0 ? cmin : 0,
    connectionsMax: Number.isFinite(cmax) && cmax > 0 ? cmax : 0,
    recentActivityDays: ra != null && Number.isFinite(ra) && ra > 0 ? ra : null,
    searchScope: VALID_SCOPE.includes(scope) ? scope : "titleSummary",
    sortBy: VALID_SORT_BY.includes(sortBy) ? sortBy : "connections",
    sortDir: VALID_SORT_DIR.includes(sortDir) ? sortDir : "desc",
    massMin: Number.isFinite(mass) && mass > 0 ? mass : 0,
    query: p.get("q") || "",
  };
}
