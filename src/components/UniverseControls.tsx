import type { CSSProperties } from "react";

export type EdgesMode = "none" | "selected" | "top5" | "top20" | "all";
export type SpacetimeMode = "off" | "grid" | "playground";
export type SpacetimePalette = "cool" | "warm" | "duo";
export type SpacetimeGrabTarget = "nodes" | "galaxies";

export interface UniverseSettings {
  edgesMode: EdgesMode;
  autoOrbit: boolean;
}

interface Props {
  value: UniverseSettings;
  onChange: (next: UniverseSettings) => void;
  style?: CSSProperties;

  // ── Reset view — optional; if omitted the button is not rendered ─────────
  onReset?: () => void;
  onFocusSelected?: () => void;
  canFocusSelected?: boolean;

  // ── Spacetime (F5) — optional; if omitted the section is not rendered ────
  spacetimeMode?: SpacetimeMode;
  onSpacetimeModeChange?: (mode: SpacetimeMode) => void;
  spacetimeIntensity?: number;
  onSpacetimeIntensityChange?: (n: number) => void;
  spacetimePalette?: SpacetimePalette;
  onSpacetimePaletteChange?: (p: SpacetimePalette) => void;
  spacetimeGrabTarget?: SpacetimeGrabTarget;
  onSpacetimeGrabTargetChange?: (t: SpacetimeGrabTarget) => void;
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
  right: 16,
  zIndex: 30,
  background: "rgba(0,8,20,0.78)",
  border: "1px solid rgba(0,240,255,0.28)",
  color: "#c8d4e8",
  fontFamily: "monospace",
  fontSize: 11,
  padding: "10px 12px",
  minWidth: 200,
  maxWidth: 240,
  maxHeight: "calc(100vh - 96px)",
  overflowY: "auto",
  backdropFilter: "blur(8px)",
};

const resetBtnStyle: CSSProperties = {
  display: "block",
  width: "100%",
  padding: "5px 10px",
  marginBottom: 8,
  background: "rgba(0,240,255,0.08)",
  border: "1px solid rgba(0,240,255,0.35)",
  color: "var(--nav-accent)",
  fontFamily: "monospace",
  fontSize: 10,
  textTransform: "uppercase",
  letterSpacing: "0.14em",
  cursor: "pointer",
};

const rowStyle: CSSProperties = { marginBottom: 8 };
const labelStyle: CSSProperties = {
  fontSize: 9,
  letterSpacing: "0.14em",
  textTransform: "uppercase",
  opacity: 0.6,
  marginBottom: 4,
  color: "var(--nav-accent)",
};

const chipStyle = (active: boolean): CSSProperties => ({
  display: "inline-block",
  padding: "3px 7px",
  marginRight: 4,
  marginBottom: 3,
  background: active ? "rgba(0,240,255,0.18)" : "transparent",
  border: `1px solid ${active ? "rgba(0,240,255,0.45)" : "rgba(255,255,255,0.10)"}`,
  color: active ? "var(--nav-accent)" : "#c8d4e8",
  cursor: "pointer",
  fontSize: 10,
});

const SPACETIME_MODES: Array<{ v: SpacetimeMode; label: string }> = [
  { v: "off",        label: "Off" },
  { v: "grid",       label: "Grid" },
  { v: "playground", label: "Playground" },
];

// Spacetime palette dots are shader-side hex values, not CSS chrome —
// need literal hex here so SpacetimeGrid can parse them.
const PALETTE_COLORS: Record<SpacetimePalette, string> = {
  cool: "#22d3ee",
  warm: "#ff7a4a",
  duo:  "#c86adf",
};

const paletteChipStyle = (color: string, active: boolean): CSSProperties => ({
  display: "inline-block",
  width: 14,
  height: 14,
  marginRight: 5,
  borderRadius: 3,
  background: color,
  border: active
    ? `1px solid rgba(255,255,255,0.9)`
    : `1px solid rgba(255,255,255,0.15)`,
  boxShadow: active ? `0 0 6px ${color}` : "none",
  cursor: "pointer",
  verticalAlign: "middle",
});

export default function UniverseControls({
  value,
  onChange,
  style,
  onReset,
  onFocusSelected,
  canFocusSelected = false,
  spacetimeMode,
  onSpacetimeModeChange,
  spacetimeIntensity,
  onSpacetimeIntensityChange,
  spacetimePalette,
  onSpacetimePaletteChange,
  spacetimeGrabTarget,
  onSpacetimeGrabTargetChange,
}: Props) {
  const showSpacetime =
    spacetimeMode !== undefined && onSpacetimeModeChange !== undefined;

  return (
    <div role="group" aria-label="Graph view controls" style={{ ...panelStyle, ...style }}>
      {onReset && (
        <button type="button" onClick={onReset} style={resetBtnStyle}>
          Fit universe
        </button>
      )}
      {onFocusSelected && (
        <button
          type="button"
          onClick={onFocusSelected}
          disabled={!canFocusSelected}
          style={{ ...resetBtnStyle, opacity: canFocusSelected ? 1 : 0.45 }}
        >
          Focus selected
        </button>
      )}

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
        <div style={{ marginTop: 6, fontSize: 9, lineHeight: 1.55, opacity: 0.72 }}>
          Drag rotate · Shift/right-drag pan · Wheel/pinch zoom
          <br />
          WASD/arrows move · Q/E vertical · F focus · Space fit
        </div>
      </div>

      {showSpacetime && (
        <div style={rowStyle}>
          <div style={labelStyle}>Spacetime</div>
          <div>
            {SPACETIME_MODES.map(({ v, label }) => (
              <button
                key={v}
                style={chipStyle(spacetimeMode === v)}
                onClick={() => onSpacetimeModeChange!(v)}
              >
                {label}
              </button>
            ))}
          </div>

          {spacetimeMode !== "off" && (
            <>
              {onSpacetimeIntensityChange && (
                <div style={{ marginTop: 6 }}>
                  <div style={{ ...labelStyle, marginBottom: 2 }}>
                    Intensity {(spacetimeIntensity ?? 0.6).toFixed(2)}
                  </div>
                  <input
                    type="range"
                    min={0}
                    max={1}
                    step={0.02}
                    value={spacetimeIntensity ?? 0.6}
                    onChange={(e) => onSpacetimeIntensityChange(parseFloat(e.target.value))}
                    style={{ width: "100%" }}
                  />
                </div>
              )}

              {onSpacetimePaletteChange && (
                <div style={{ marginTop: 4 }}>
                  <div style={{ ...labelStyle, marginBottom: 2 }}>Palette</div>
                  {(Object.keys(PALETTE_COLORS) as SpacetimePalette[]).map((p) => (
                    <span
                      key={p}
                      title={p}
                      style={paletteChipStyle(PALETTE_COLORS[p], spacetimePalette === p)}
                      onClick={() => onSpacetimePaletteChange(p)}
                    />
                  ))}
                </div>
              )}

              {spacetimeMode === "playground" && onSpacetimeGrabTargetChange && (
                <div style={{ marginTop: 6 }}>
                  <div style={{ ...labelStyle, marginBottom: 2 }}>Drag</div>
                  {(["nodes", "galaxies"] as SpacetimeGrabTarget[]).map((t) => (
                    <button
                      key={t}
                      style={chipStyle((spacetimeGrabTarget ?? "nodes") === t)}
                      onClick={() => onSpacetimeGrabTargetChange(t)}
                      title={
                        t === "galaxies"
                          ? "Grab a whole galaxy — its members translate together and the fabric warps around the moving center of mass."
                          : "Grab individual heavy nodes."
                      }
                    >
                      {t === "nodes" ? "Nodes" : "Galaxies"}
                    </button>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
