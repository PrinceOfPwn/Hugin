/*
 * SpacetimeLayer — a single-mount R3F composition for the spacetime
 * experience: a curved wireframe of "spacetime", grab-drag of heavy nodes,
 * and a release-pulse gravity ripple.
 *
 * INTEGRATION (do this ONCE in GraphThreeV3.tsx):
 *
 * import SpacetimeLayer from "./SpacetimeLayer";
 * ...
 * const [spacetimeMode, setSpacetimeMode] = useState<"off"|"grid"|"playground">("off");
 * const [spacetimeIntensity, setSpacetimeIntensity] = useState(0.6);
 * const [spacetimePalette, setSpacetimePalette] = useState<"cool"|"warm"|"duo">("duo");
 * ...
 * // Inside <Canvas>:
 * <SpacetimeLayer
 *   mode={spacetimeMode}
 *   entities={visibleEntities}
 *   intensity={spacetimeIntensity}
 *   paletteHint={spacetimePalette}
 *   onNodeMoved={(id, pos) => setNodePosition(id, pos)}
 * />
 *
 * // Wire the new UniverseControls props (already extended):
 * <UniverseControls
 *   ...existingProps
 *   spacetimeMode={spacetimeMode}
 *   onSpacetimeModeChange={setSpacetimeMode}
 *   spacetimeIntensity={spacetimeIntensity}
 *   onSpacetimeIntensityChange={setSpacetimeIntensity}
 *   spacetimePalette={spacetimePalette}
 *   onSpacetimePaletteChange={setSpacetimePalette}
 * />
 */

import { useMemo, useRef, useState } from "react";
import type { Entity } from "../lib/types";
import SpacetimeGrid, { type SpacetimeHeavyNode } from "./SpacetimeGrid";
import PlanetGrabber, { type GrabCandidate } from "./PlanetGrabber";
import GravityPulse from "./GravityPulse";

interface Props {
  mode: "off" | "grid" | "playground";
  entities: Entity[];
  onNodeMoved?: (id: string, newPosition: [number, number, number]) => void;
  intensity?: number;
  paletteHint?: "cool" | "warm" | "duo";
}

const HEAVY_K = 16;
const ATTRACTOR_MASS_MIN = 3.0;

export default function SpacetimeLayer({
  mode,
  entities,
  onNodeMoved,
  intensity = 0.6,
  paletteHint = "duo",
}: Props) {
  // ── Derive heavy nodes for the grid displacement ──────────────────────────
  const heavyNodes: SpacetimeHeavyNode[] = useMemo(() => {
    if (mode === "off") return [];
    const withMass = entities.filter(
      (e) => (e.mass ?? 0) > 0 && e.position !== undefined,
    );
    // top-K by mass
    withMass.sort((a, b) => (b.mass ?? 0) - (a.mass ?? 0));
    return withMass.slice(0, HEAVY_K).map((e) => ({
      id: e.id,
      position: [e.position!.x, e.position!.y, e.position!.z] as [number, number, number],
      mass: e.mass ?? 1,
    }));
  }, [entities, mode]);

  // ── Grabber candidates: all attractors, wider than heavy set ──────────────
  const hitCandidates: GrabCandidate[] = useMemo(() => {
    if (mode !== "playground") return [];
    const out: GrabCandidate[] = [];
    for (const e of entities) {
      const m = e.mass ?? 0;
      if (m < ATTRACTOR_MASS_MIN || !e.position) continue;
      // Hitbox scales with mass — bigger stars are easier to grab. Clamped.
      const size = 8 + Math.min(24, m * 2.5);
      out.push({
        id: e.id,
        position: [e.position.x, e.position.y, e.position.z],
        size,
        mass: m,
      });
    }
    return out;
  }, [entities, mode]);

  // Live overrides — while user drags a node, we render it at the drag pos.
  // (Also passed back to the parent via onNodeMoved so satellites can follow.)
  const [pulse, setPulse] = useState<{ origin: [number, number, number]; triggerId: number } | null>(null);

  // We keep an override buffer for heavy positions so the grid deforms live
  // while the user drags. This shadows the value from `entities` for that id.
  const overridesRef = useRef<Map<string, [number, number, number]>>(new Map());

  const heavyNodesLive = useMemo(() => {
    if (overridesRef.current.size === 0) return heavyNodes;
    return heavyNodes.map((n) => {
      const o = overridesRef.current.get(n.id);
      return o ? { ...n, position: o } : n;
    });
  // Re-derive when heavyNodes changes OR when we bump the pulse (a proxy for
  // drag activity). Cheap — HEAVY_K is 16.
  }, [heavyNodes, pulse]);

  if (mode === "off") return null;

  return (
    <group>
      <SpacetimeGrid
        heavyNodes={heavyNodesLive}
        visible={true}
        intensity={intensity}
        paletteHint={paletteHint}
      />

      {mode === "playground" && (
        <>
          <PlanetGrabber
            hitCandidates={hitCandidates}
            enabled={true}
            mode="spring-back"
            onGrabStart={() => { /* noop — hook for future haptics */ }}
            onGrabMove={(id, pos) => {
              overridesRef.current.set(id, [pos.x, pos.y, pos.z]);
              // Bump a state to re-derive heavyNodesLive. Cheap because the
              // dependency-free memo is tiny (HEAVY_K entries).
              setPulse((p) => (p ? { ...p } : p));
              onNodeMoved?.(id, [pos.x, pos.y, pos.z]);
            }}
            onGrabEnd={(id, finalPos) => {
              // Fire a gravity pulse at the node's spring origin (approx —
              // we use the current finalPos as the visual anchor).
              setPulse({
                origin: [finalPos.x, 0.1, finalPos.z],   // pulse rides on the mesh
                triggerId: Date.now(),
              });
              overridesRef.current.delete(id);
              // Note: spring-back tween is owned by PlanetGrabber; parent
              // will see the node snap once the grabber's own state clears.
            }}
          />

          <GravityPulse
            origin={pulse?.origin ?? null}
            triggerId={pulse?.triggerId}
            color="#00f0ff"
            speed={250}
            duration={1.8}
          />
        </>
      )}
    </group>
  );
}
