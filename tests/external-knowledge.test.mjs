import assert from "node:assert/strict";
import {
  MAX_EVIDENCE_CHARS,
  chunkPdfText,
  chunkPlainText,
  decodeHtmlEntities,
  htmlToText,
  normalizeUnitSourceRefs,
  packByChars,
  renderKnowledgeUnit,
  toCanonicalRecords,
  validateKnowledgeUnits,
} from "../scripts/lib/external-knowledge.mjs";

let passed = 0;
function test(name, fn) {
  process.stdout.write(`[external-knowledge] ${name} ... `);
  fn();
  passed++;
  console.log("OK");
}

test("PDF page chunking preserves page provenance and overlap", () => {
  const pdfText = [
    "Page one " + "A".repeat(80),
    "Page two " + "B".repeat(80),
    "Page three " + "C".repeat(80),
  ].join("\f");
  const chunks = chunkPdfText(pdfText, { chunkChars: 200, overlapPages: 1 });
  assert.ok(chunks.length >= 2);
  assert.equal(chunks[0].page_start, 1);
  assert.ok(chunks[0].page_end >= 1);
  assert.ok(chunks[1].page_start <= chunks[0].page_end, "second chunk should overlap page provenance");
});

test("oversized PDF pages are split below the chunk budget", () => {
  const chunks = chunkPdfText("A".repeat(1300), { chunkChars: 300, overlapPages: 1 });
  assert.ok(chunks.length >= 4);
  assert.ok(chunks.every((chunk) => chunk.text.length <= 300));
  assert.ok(chunks.every((chunk) => chunk.page_start === 1 && chunk.page_end === 1));
});

test("plain web text is chunked without losing content order", () => {
  const text = ["alpha ".repeat(80), "beta ".repeat(80), "gamma ".repeat(80)].join("\n\n");
  const chunks = chunkPlainText(text, { chunkChars: 420, overlapChars: 30 });
  assert.ok(chunks.length >= 2);
  assert.ok(chunks[0].text.includes("alpha"));
  assert.ok(chunks.at(-1).text.includes("gamma"));
});

test("HTML extraction drops scripts and survives invalid numeric entities", () => {
  const parsed = htmlToText(`<html><head><title>Bug Bounty Note</title><style>.x{}</style></head><body><h1>IDOR</h1><p>Change the object identifier.</p><script>alert(1)</script></body></html>`);
  assert.equal(parsed.title, "Bug Bounty Note");
  assert.match(parsed.text, /IDOR/);
  assert.match(parsed.text, /Change the object identifier/);
  assert.doesNotMatch(parsed.text, /alert\(1\)/);
  assert.equal(decodeHtmlEntities("bad &#999999999; entity"), "bad &#999999999; entity");
});

test("character batching keeps all items exactly once", () => {
  const items = Array.from({ length: 9 }, (_, i) => ({ id: i, body: "x".repeat(100) }));
  const batches = packByChars(items, 500, 3);
  assert.deepEqual(batches.flat().map((item) => item.id), items.map((item) => item.id));
  assert.ok(batches.every((batch) => batch.length <= 3));
});

test("knowledge validation grounds source refs and every graph claim", () => {
  const chunksById = fixtureChunks();
  const unit = fixtureUnit();
  unit.source_refs = [{
    title: "Source",
    url: "https://example.test/book.pdf",
    page_start: 10,
    page_end: 10,
    chunk_ids: ["c1"],
    evidence: ["changes the object identifier"],
  }];
  assert.deepEqual(validateKnowledgeUnits({ units: [unit] }, { chunksById }), []);

  unit.source_refs[0].url = "https://wrong.test/book.pdf";
  assert.ok(validateKnowledgeUnits({ units: [unit] }, { chunksById }).some((error) => /url must match/.test(error)));
  unit.source_refs[0].url = "https://example.test/book.pdf";

  unit.relations[0].target = "Invented remote node";
  assert.ok(validateKnowledgeUnits({ units: [unit] }, { chunksById }).some((error) => /endpoints must reuse names/.test(error)));
  unit.relations[0].target = "Object-level authorization";

  unit.techniques[0].evidence = ["invented technique evidence"];
  assert.ok(validateKnowledgeUnits({ units: [unit] }, { chunksById }).some((error) => /source chunks/.test(error)));
  unit.techniques[0].evidence = ["changes the object identifier"];

  unit.tool_usage = [{ tool: "HTTP proxy" }];
  assert.ok(validateKnowledgeUnits({ units: [unit] }, { chunksById }).some((error) => /tool_usage/.test(error)));
  unit.tool_usage = fixtureUnit().tool_usage;

  unit.source_refs[0].evidence = ["not present in source"];
  assert.ok(validateKnowledgeUnits({ units: [unit] }, { chunksById }).some((error) => /not an exact short quote/.test(error)));
  unit.source_refs[0].evidence = ["x".repeat(MAX_EVIDENCE_CHARS + 1)];
  assert.ok(validateKnowledgeUnits({ units: [unit] }, { chunksById }).length > 0);
});

test("provenance normalization is derived from chunks, not model metadata", () => {
  const chunksById = fixtureChunks();
  const unit = fixtureUnit();
  unit.source_refs = [{
    title: "hallucinated title",
    url: "https://wrong.test/book.pdf",
    page_start: 999,
    page_end: 999,
    chunk_ids: ["c1"],
    evidence: ["changes the object identifier"],
  }];
  const normalized = normalizeUnitSourceRefs(unit, chunksById);
  assert.equal(normalized.source_refs[0].title, "Source Book");
  assert.equal(normalized.source_refs[0].url, "https://example.test/book.pdf");
  assert.equal(normalized.source_refs[0].page_start, 10);
  assert.equal(normalized.source_refs[0].page_end, 10);
  assert.equal(normalized.source_refs[0].source_sha256, "fixture-source-sha256");
});

test("rendered knowledge is operational and exposes auditable web provenance", () => {
  const unit = fixtureUnit();
  const body = renderKnowledgeUnit(unit);
  assert.match(body, /## Operational objective/);
  assert.match(body, /## Operator flow/);
  assert.match(body, /## Validation signals/);
  assert.match(body, /\[Source Book\]\(https:\/\/example\.test\/book\.pdf\)/);
  assert.doesNotMatch(body, /RAW CHUNK/);
});

test("canonical output uses stable collection ownership", () => {
  const records = toCanonicalRecords([fixtureUnit()], {
    id: "fixture-collection",
    title: "Fixture Collection",
    source: "https://example.test/collection",
    knowledge_profile: "offensive-web",
    language: "en",
  });
  assert.equal(records.length, 1);
  const record = records[0];
  assert.equal(record.schema_version, "hugin.canonical.v2");
  assert.equal(record.kind, "playbook");
  assert.equal(record.publish_state, "core");
  assert.equal(record.enrichment.model, "z-ai/glm-5.2");
  assert.equal(record.source.input_file, "external:fixture-collection");
  assert.ok(record.enrichment.techniques.length > 0);
});

function fixtureChunks() {
  return new Map([["c1", {
    id: "c1",
    body: "A tester changes the object identifier and compares authorization behavior.",
    source_document: {
      source_id: "fixture-source",
      source_title: "Source Book",
      source_url: "https://example.test/book.pdf",
      source_sha256: "fixture-source-sha256",
      page_start: 10,
      page_end: 10,
    },
  }]]);
}

function fixtureUnit() {
  return {
    unit_key: "idor-object-reference-authorization-test",
    title: "Object Reference Authorization Testing",
    knowledge_type: "testing_strategy",
    summary: "Test whether changing an object reference crosses an authorization boundary.",
    objective: "Demonstrate unauthorized access to another object's data or action.",
    applicability: "An authenticated endpoint accepts a user-controlled object identifier.",
    prerequisites: ["At least two distinguishable objects or principals."],
    attack_surface: ["Path identifiers", "JSON object ids"],
    operator_flow: [
      { action: "Capture a valid request for an object you can access.", why: "Establish a working baseline." },
      { action: "Change only the object identifier and replay the request.", why: "Isolate the authorization decision." },
    ],
    decision_points: [{ condition: "The response returns another object's data", action: "Confirm the boundary with a second object", rationale: "Reduce false positives." }],
    validation_signals: ["A stable unauthorized cross-object response with the same session."],
    pivots: ["Test sibling endpoints that reuse the same identifier."],
    failure_modes: ["A 200 response can still contain an authorization error in the body."],
    tool_usage: [{ tool: "HTTP proxy", use: "Replay and compare requests", pattern: "Change one identifier at a time" }],
    source_refs: [{ title: "Source Book", url: "https://example.test/book.pdf", source_sha256: "fixture-source-sha256", page_start: 10, page_end: 11, chunk_ids: ["c1"], evidence: ["changes the object identifier"] }],
    tags: ["idor", "authorization", "web"],
    concepts: [{ name: "Object-level authorization", type: "security_boundary", description: "Authorization decision tied to a referenced object.", confidence: 0.9, evidence: ["changes the object identifier"] }],
    techniques: [{ name: "Object Reference Mutation", description: "Mutate an object identifier while holding the session constant.", phase: "testing", confidence: 0.9, evidence: ["changes the object identifier"] }],
    entities: [{ name: "object identifier", type: "input", confidence: 0.9, evidence: ["changes the object identifier"] }],
    relations: [{ source: "Object Reference Mutation", target: "Object-level authorization", type: "validates", description: "The mutation probes the authorization boundary.", confidence: 0.88, evidence: ["changes the object identifier"] }],
    mitre_candidates: [],
  };
}

console.log(`\n[external-knowledge] all ${passed} tests passed`);
