import type { CSSProperties, MouseEvent } from "react";
import type { Entity } from "../lib/types";

interface Props {
  entity: Entity;
  galaxyName?: string;
  selected: boolean;
  variant: "grid" | "list";
  routePrefix: string;
  onSelect: (id: string, ev: MouseEvent) => void;
}

const MITRE_RE = /^T\d{4}(?:\.\d+)?$/;

// ─── Spanish delta formatter ─────────────────────────────────────────────────
function fmtDelta(iso: string | null | undefined): string | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return null;
  const diff = Date.now() - t;
  if (diff < 0) return "en el futuro";
  const days = Math.floor(diff / 86400000);
  if (days === 0) return "hoy";
  if (days === 1) return "ayer";
  if (days < 30) return `hace ${days} días`;
  const months = Math.floor(days / 30);
  if (months < 12) return `hace ${months} mes${months === 1 ? "" : "es"}`;
  const years = Math.floor(days / 365);
  return `hace ${years} año${years === 1 ? "" : "s"}`;
}

export default function EntityListCard({
  entity, galaxyName, selected, variant, routePrefix, onSelect,
}: Props) {
  const mitreChips = (entity.tags || []).filter((t) => MITRE_RE.test(t));
  const shownMitre = mitreChips.slice(0, 3);
  const overflow = Math.max(0, mitreChips.length - shownMitre.length);
  const delta = fmtDelta(entity.firstSeenAt || entity.lastUpdatedAt);
  const href = `${routePrefix}${entity.route}`;
  const cardStyle = variant === "grid" ? gridCardStyle : listCardStyle;
  const summary = (entity.summary || "").trim();

  return (
    <a
      href={href}
      onClick={(ev) => onSelect(entity.id, ev)}
      style={{ ...cardStyle, ...(selected ? selectedStyle : null) }}
      data-explorer-card={entity.id}
      aria-selected={selected}
      role="option"
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", gap: 8 }}>
        <h3 style={titleStyle}>{entity.title}</h3>
        {delta && <span style={deltaStyle}>{delta}</span>}
      </div>

      <div style={metaRowStyle}>
        <span style={badge}>{galaxyName || entity.galaxyId}</span>
        {entity.tier && <span style={badge}>Tier {entity.tier}</span>}
        {entity.mass != null && <span style={badge}>m {entity.mass.toFixed(1)}</span>}
        <span style={badgeMuted} title="Connections">◈ {entity.degree ?? 0}</span>
        {shownMitre.map((m) => <span key={m} style={mitreChip}>{m}</span>)}
        {overflow > 0 && <span style={badgeMuted}>+{overflow}</span>}
      </div>

      {summary && (
        <p style={variant === "grid" ? summaryGridStyle : summaryListStyle}>
          {summary}
        </p>
      )}
    </a>
  );
}

// ─── Styles ──────────────────────────────────────────────────────────────────
const listCardStyle: CSSProperties = {
  display: "block",
  padding: "10px 12px",
  border: "1px solid rgba(0,240,255,0.14)",
  background: "rgba(0,8,20,0.5)",
  color: "#e8f0ff",
  textDecoration: "none",
  transition: "border-color 0.12s ease, background 0.12s ease",
};

const gridCardStyle: CSSProperties = {
  ...listCardStyle,
  padding: "12px 14px",
  height: "100%",
  minHeight: 140,
};

const selectedStyle: CSSProperties = {
  borderColor: "#00f0ff",
  background: "rgba(0,60,90,0.55)",
  boxShadow: "0 0 0 1px rgba(0,240,255,0.4)",
};

const titleStyle: CSSProperties = {
  margin: 0,
  fontSize: 14,
  fontWeight: 600,
  color: "#e8f0ff",
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
  flex: 1,
  minWidth: 0,
};

const deltaStyle: CSSProperties = {
  fontFamily: "monospace",
  fontSize: 10,
  background: "rgba(0,240,255,0.12)",
  color: "#00f0ff",
  padding: "1px 6px",
  whiteSpace: "nowrap",
};

const metaRowStyle: CSSProperties = {
  display: "flex",
  flexWrap: "wrap",
  gap: 4,
  marginTop: 6,
  fontFamily: "monospace",
  fontSize: 10,
};

const badge: CSSProperties = {
  padding: "1px 6px",
  background: "rgba(0,240,255,0.12)", color: "#00f0ff",
  border: "1px solid rgba(0,240,255,0.28)",
};
const badgeMuted: CSSProperties = {
  padding: "1px 6px",
  background: "rgba(255,255,255,0.05)", color: "#c8d4e8",
  border: "1px solid rgba(255,255,255,0.12)",
};
const mitreChip: CSSProperties = {
  padding: "1px 6px",
  background: "rgba(157,124,244,0.14)",
  color: "#d8cdfa",
  border: "1px solid rgba(157,124,244,0.35)",
};

const summaryListStyle: CSSProperties = {
  margin: "6px 0 0",
  fontSize: 12,
  lineHeight: 1.45,
  color: "#cbd5e1",
  display: "-webkit-box",
  WebkitLineClamp: 2,
  WebkitBoxOrient: "vertical" as any,
  overflow: "hidden",
};
const summaryGridStyle: CSSProperties = {
  ...summaryListStyle,
  WebkitLineClamp: 3,
};
