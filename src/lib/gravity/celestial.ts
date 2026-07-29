/**
 * Presentation-only celestial metadata. These are deterministic metaphors for
 * investigating a knowledge body; they are never source facts about a record.
 */
export interface CelestialReadout {
  density: number;
  surfaceTemperatureK: number;
  rotationHours: number;
  orbitalPeriodHu: number | null;
  classification: "asteroid" | "terrestrial" | "gas giant" | "stellar anchor";
}

export function deriveCelestialReadout(input: { mass: number; radius: number; velocity?: readonly [number, number, number]; distanceFromCenter?: number }): CelestialReadout {
  const mass = Math.max(0.01, input.mass);
  const radius = Math.max(0.1, input.radius);
  const speed = Math.hypot(input.velocity?.[0] ?? 0, input.velocity?.[1] ?? 0, input.velocity?.[2] ?? 0);
  const density = mass / ((4 / 3) * Math.PI * radius ** 3);
  const classification = mass > 80 ? "stellar anchor" : mass > 18 ? "gas giant" : mass > 2.5 ? "terrestrial" : "asteroid";
  // A bounded visual thermal scale: mass/density suggest emitted influence,
  // not a physical temperature measurement of the source knowledge.
  const surfaceTemperatureK = Math.round(180 + Math.min(3200, 115 * Math.log1p(mass * density * 10)));
  const rotationHours = Number((4 + 28 / (1 + Math.log1p(mass))).toFixed(2));
  const orbitalPeriodHu = input.distanceFromCenter && speed > 0.001 ? Number((2 * Math.PI * input.distanceFromCenter / speed).toFixed(2)) : null;
  return { density: Number(density.toFixed(3)), surfaceTemperatureK, rotationHours, orbitalPeriodHu, classification };
}
