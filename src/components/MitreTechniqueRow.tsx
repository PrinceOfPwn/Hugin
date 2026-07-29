import type { CSSProperties } from "react";
import type { MitreIndexEntity, MitreIndexTechnique } from "../lib/mitre-index";

interface Props {
  technique: MitreIndexTechnique;
  entities: MitreIndexEntity[]; // pre-filtered to this technique
  routePrefix: string;
  expanded: boolean;
  onToggle: () => void;
  highlight?: boolean;
}

export default function MitreTechniqueRow({
  technique,
  entities,
  routePrefix,
  expanded,
  onToggle,
  highlight = false,
}: Props) {
  const attackUrl = `https://attack.mitre.org/techniques/${technique.id}/`;
  const cardStyle: CSSProperties = {
    ...cardBase,
    borderColor: highlight ? "#ffd447" : cardBase.borderColor,
    boxShadow: highlight ? "0 0 0 1px rgba(255,212,71,0.5)" : "none",
  };
  return (
    <div style={cardStyle} data-mitre-id={technique.id}>
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={expanded}
        style={headerButton}
      >
        <span style={idBadge}>{technique.id}</span>
        <span style={countPill}>{technique.cardCount}</span>
        <span style={caret} aria-hidden="true">{expanded ? "▾" : "▸"}</span>
      </button>
      {expanded && (
        <div style={expandedWrap}>
          <ul style={list}>
            {entities.slice(0, 40).map((e) => (
              <li key={e.id} style={listItem}>
                <a href={`${routePrefix}${e.route}`} style={link}>
                  {e.title}
                </a>
                {e.mass != null && (
                  <span style={massBadge}>mass {e.mass.toFixed(1)}</span>
                )}
              </li>
            ))}
            {entities.length > 40 && (
              <li style={{ ...listItem, opacity: 0.6, fontStyle: "italic" }}>
                +{entities.length - 40} more…
              </li>
            )}
          </ul>
          <a href={attackUrl} target="_blank" rel="noopener noreferrer" style={attackLink}>
            View {technique.id} on attack.mitre.org →
          </a>
        </div>
      )}
    </div>
  );
}

const cardBase: CSSProperties = {
  border: "1px solid rgba(0,240,255,0.24)",
  background: "rgba(0,8,20,0.6)",
  borderRadius: 3,
  minWidth: 130,
  flex: "0 0 auto",
  transition: "border-color 0.2s",
};
const headerButton: CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: 6,
  width: "100%",
  padding: "8px 10px",
  background: "transparent",
  border: "none",
  color: "#e8f0ff",
  fontFamily: "monospace",
  fontSize: 12,
  cursor: "pointer",
  textAlign: "left",
};
const idBadge: CSSProperties = {
  color: "#00f0ff",
  fontWeight: 700,
};
const countPill: CSSProperties = {
  marginLeft: "auto",
  padding: "1px 7px",
  background: "rgba(0,240,255,0.18)",
  color: "#00f0ff",
  border: "1px solid rgba(0,240,255,0.32)",
  fontSize: 11,
};
const caret: CSSProperties = {
  color: "#7ea8c8",
  fontSize: 11,
};
const expandedWrap: CSSProperties = {
  padding: "6px 10px 10px",
  borderTop: "1px solid rgba(0,240,255,0.14)",
};
const list: CSSProperties = {
  listStyle: "none",
  padding: 0,
  margin: 0,
  display: "grid",
  gap: 4,
};
const listItem: CSSProperties = {
  display: "flex",
  justifyContent: "space-between",
  gap: 8,
  alignItems: "baseline",
  fontFamily: "monospace",
  fontSize: 11,
};
const link: CSSProperties = {
  color: "#e8f0ff",
  textDecoration: "none",
  minWidth: 0,
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
};
const massBadge: CSSProperties = {
  fontSize: 10,
  color: "#7ea8c8",
  whiteSpace: "nowrap",
};
const attackLink: CSSProperties = {
  display: "inline-block",
  marginTop: 8,
  fontFamily: "monospace",
  fontSize: 10,
  color: "#7ea8c8",
  textDecoration: "none",
};
