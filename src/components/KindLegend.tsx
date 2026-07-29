import { useState } from "react";

const KINDS: Array<{ id: string; label: string; glyph: string; color: string }> = [
  { id: "technique", label: "Technique",    glyph: "★", color: "#ff2244" },
  { id: "chain",     label: "Attack chain", glyph: "⧫", color: "#ffb700" },
  { id: "detection", label: "Detection",    glyph: "⬡", color: "#39ff14" },
  { id: "concept",   label: "Concept",      glyph: "●", color: "#00b3e6" },
  { id: "lgtm_note", label: "Note",         glyph: "≈", color: "#00e5bf" },
  { id: "playbook",  label: "Playbook",     glyph: "▪", color: "#e040fb" },
  { id: "source",    label: "Source code",  glyph: "◆", color: "#00f0ff" },
  { id: "documentation", label: "Doc",      glyph: "▲", color: "#9d4edd" },
];

const EDGES: Array<{ id: string; label: string; color: string }> = [
  { id: "enables",       label: "enables →",       color: "#00f0ff" },
  { id: "counters",      label: "counters ⚔",      color: "#ff334c" },
  { id: "detects",       label: "detects ◈",       color: "#38ff6b" },
  { id: "chains_to",     label: "chains to ⇒",     color: "#ffb800" },
  { id: "requires",      label: "requires ←",      color: "#e13ffb" },
  { id: "implements",    label: "implements",      color: "#ffffff" },
  { id: "derived_from",  label: "derived from",    color: "#00e5bf" },
  { id: "alternative_to",label: "alternative",     color: "#9d4edd" },
];

interface Props {
  activeKinds: Set<string>;
  onToggleKind: (id: string) => void;
  activeEdgeTypes: Set<string>;
  onToggleEdgeType: (id: string) => void;
}

export default function KindLegend({ activeKinds, onToggleKind, activeEdgeTypes, onToggleEdgeType }: Props) {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div style={{
      position: "absolute",
      top: 20, left: 20,
      background: "rgba(0, 8, 20, 0.72)",
      backdropFilter: "blur(8px)",
      border: "1px solid rgba(0, 240, 255, 0.22)",
      borderRadius: 4,
      padding: collapsed ? "8px 12px" : "12px 14px",
      color: "#dae4f0",
      fontFamily: "monospace",
      fontSize: 11,
      letterSpacing: "0.05em",
      maxWidth: 220,
      pointerEvents: "auto",
      zIndex: 5,
    }}>
      <button onClick={() => setCollapsed(!collapsed)}
        style={{
          background: "transparent", border: "none", color: "var(--nav-accent)",
          fontFamily: "monospace", fontSize: 10, cursor: "pointer",
          textTransform: "uppercase", letterSpacing: "0.15em",
          padding: 0, marginBottom: collapsed ? 0 : 8,
        }}>
        {collapsed ? "▸ SIGNALS" : "▾ SIGNALS"}
      </button>

      {!collapsed && (
        <>
          <p style={{ margin: "0 0 4px", opacity: 0.6, fontSize: 9, textTransform: "uppercase", letterSpacing: "0.15em" }}>
            Node kinds
          </p>
          <div>
            {KINDS.map(k => {
              const on = activeKinds.has(k.id);
              return (
                <button key={k.id} onClick={() => onToggleKind(k.id)} title={k.label}
                  style={{
                    display: "flex", alignItems: "center", gap: 8,
                    width: "100%", padding: "3px 4px",
                    background: "transparent", border: "none",
                    color: on ? "#fff" : "#4a5568",
                    fontFamily: "monospace", fontSize: 11, cursor: "pointer",
                    textAlign: "left", opacity: on ? 1 : 0.4,
                  }}>
                  <span style={{
                    color: k.color, fontSize: 14, width: 16, textAlign: "center",
                    textShadow: on ? `0 0 8px ${k.color}` : "none",
                  }}>{k.glyph}</span>
                  <span>{k.label}</span>
                </button>
              );
            })}
          </div>

          <p style={{ margin: "10px 0 4px", opacity: 0.6, fontSize: 9, textTransform: "uppercase", letterSpacing: "0.15em" }}>
            Signal streams
          </p>
          <div>
            {EDGES.map(e => {
              const on = activeEdgeTypes.has(e.id);
              return (
                <button key={e.id} onClick={() => onToggleEdgeType(e.id)}
                  style={{
                    display: "flex", alignItems: "center", gap: 8,
                    width: "100%", padding: "2px 4px",
                    background: "transparent", border: "none",
                    color: on ? e.color : "#4a5568",
                    fontFamily: "monospace", fontSize: 10, cursor: "pointer",
                    textAlign: "left", opacity: on ? 1 : 0.35,
                  }}>
                  <span style={{
                    display: "inline-block", width: 22, height: 2,
                    background: e.color, boxShadow: on ? `0 0 6px ${e.color}` : "none",
                  }} />
                  <span>{e.label}</span>
                </button>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}
