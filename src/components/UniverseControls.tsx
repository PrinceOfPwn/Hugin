import type { CSSProperties } from "react";

export type EdgesMode = "none" | "selected" | "top5" | "top20" | "all";

export interface UniverseSettings {
  edgesMode: EdgesMode;
  autoOrbit: boolean;
  cinematic: boolean;
}

interface Props {
  value: UniverseSettings;
  onChange: (next: UniverseSettings) => void;
  style?: CSSProperties;
}

const EDGE_LABELS: Array<{ v: EdgesMode; label: string }> = [
  { v: "none",     label: "None" },
  { v: "selected", label: "Selected" },
  { v: "top5",     label: "Top 5%" },
  { v: "top20",    label: "Top 20%" },
  { v: "all",      label: "All" },
];

const panelStyle: CSSProperties = {
  position: "absolute",
  top: 16,
  right: 76,      // leaves room for the Reset view button
  zIndex: 5,
  background: "rgba(0,8,20,0.78)",
  border: "1px solid rgba(0,240,255,0.28)",
  color: "#c8d4e8",
  fontFamily: "monospace",
  fontSize: 11,
  padding: "10px 12px",
  minWidth: 200,
  backdropFilter: "blur(8px)",
};

const rowStyle: CSSProperties = { marginBottom: 8 };
const labelStyle: CSSProperties = {
  fontSize: 9,
  letterSpacing: "0.14em",
  textTransform: "uppercase",
  opacity: 0.6,
  marginBottom: 4,
  color: "#00f0ff",
};

const chipStyle = (active: boolean): CSSProperties => ({
  display: "inline-block",
  padding: "3px 7px",
  marginRight: 4,
  marginBottom: 3,
  background: active ? "rgba(0,240,255,0.18)" : "transparent",
  border: `1px solid ${active ? "rgba(0,240,255,0.45)" : "rgba(255,255,255,0.10)"}`,
  color: active ? "#00f0ff" : "#c8d4e8",
  cursor: "pointer",
  fontSize: 10,
});

export default function UniverseControls({ value, onChange, style }: Props) {
  return (
    <div style={{ ...panelStyle, ...style }}>
      <div style={rowStyle}>
        <div style={labelStyle}>Edges</div>
        <div>
          {EDGE_LABELS.map(({ v, label }) => (
            <button
              key={v}
              style={chipStyle(value.edgesMode === v)}
              onClick={() => onChange({ ...value, edgesMode: v })}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <div style={rowStyle}>
        <div style={labelStyle}>Camera</div>
        <label style={{ display: "inline-flex", alignItems: "center", gap: 6, marginRight: 10 }}>
          <input
            type="checkbox"
            checked={value.autoOrbit}
            onChange={(e) => onChange({ ...value, autoOrbit: e.target.checked })}
          />
          Auto-orbit
        </label>
        <label style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
          <input
            type="checkbox"
            checked={value.cinematic}
            onChange={(e) => onChange({ ...value, cinematic: e.target.checked })}
          />
          Cinematic
        </label>
      </div>
    </div>
  );
}
