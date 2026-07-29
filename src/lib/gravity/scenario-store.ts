/** Local-first scenario persistence. Canonical HUGIN data is never written here. */
export interface BodyOverride { entityId: string; position: [number, number, number]; velocity: [number, number, number]; mass?: number; }
export interface StoredScenario {
  schemaVersion: "1";
  id: string;
  name: string;
  datasetVersion: string;
  createdAt: string;
  updatedAt: string;
  simulationTime: number;
  bodyOverrides: BodyOverride[];
  events: Array<{ type: string; at: number; payload: unknown }>;
  relationDrafts: Array<{ source: string; target: string; type: string; rationale?: string }>;
}

const DB = "hugin-gravity-lab";
const STORE = "scenarios";

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE, { keyPath: "id" });
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export async function saveScenario(scenario: StoredScenario) {
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const transaction = db.transaction(STORE, "readwrite");
    transaction.objectStore(STORE).put({ ...scenario, updatedAt: new Date().toISOString() });
    transaction.oncomplete = () => resolve(); transaction.onerror = () => reject(transaction.error);
  });
  db.close();
}

export async function loadScenario(id: string): Promise<StoredScenario | null> {
  const db = await openDb();
  const scenario = await new Promise<StoredScenario | null>((resolve, reject) => {
    const request = db.transaction(STORE, "readonly").objectStore(STORE).get(id);
    request.onsuccess = () => resolve(request.result ?? null); request.onerror = () => reject(request.error);
  });
  db.close(); return scenario;
}

export async function listScenarios(): Promise<StoredScenario[]> {
  const db = await openDb();
  const scenarios = await new Promise<StoredScenario[]>((resolve, reject) => {
    const request = db.transaction(STORE, "readonly").objectStore(STORE).getAll();
    request.onsuccess = () => resolve(request.result ?? []); request.onerror = () => reject(request.error);
  });
  db.close(); return scenarios.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
}

export async function requestDurableStorage() {
  if (!navigator.storage?.persist) return false;
  return navigator.storage.persist();
}

export function createScenario(name: string, datasetVersion: string): StoredScenario {
  const now = new Date().toISOString();
  return { schemaVersion: "1", id: crypto.randomUUID(), name, datasetVersion, createdAt: now, updatedAt: now, simulationTime: 0, bodyOverrides: [], events: [], relationDrafts: [] };
}

export function exportScenario(scenario: StoredScenario) { return JSON.stringify(scenario, null, 2); }

export function importScenario(raw: string): StoredScenario {
  const scenario = JSON.parse(raw) as StoredScenario;
  if (scenario.schemaVersion !== "1" || !scenario.id || !Array.isArray(scenario.bodyOverrides)) throw new Error("Invalid HUGIN Gravity Lab scenario.");
  return scenario;
}
