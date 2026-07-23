import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const generated = path.resolve("src/generated");
const output = path.resolve("release");
const entities = JSON.parse(fs.readFileSync(path.join(generated, "entities.json"), "utf8"));
const evidence = JSON.parse(fs.readFileSync(path.join(generated, "evidence.json"), "utf8"));
const relations = JSON.parse(fs.readFileSync(path.join(generated, "curated-relations.json"), "utf8"));
const manifest = JSON.parse(fs.readFileSync(path.join(generated, "manifest.json"), "utf8"));
fs.mkdirSync(output, { recursive: true });

const csv = (value) => `"${String(value ?? "").replaceAll('"', '""')}"`;
fs.writeFileSync(path.join(output, "hugin-entities.jsonl"), `${entities.map((entity) => JSON.stringify(entity)).join("\n")}\n`);
fs.writeFileSync(path.join(output, "hugin-evidence.jsonl"), `${evidence.map((item) => JSON.stringify(item)).join("\n")}\n`);
fs.writeFileSync(path.join(output, "hugin-entities.csv"), [
  ["id", "slug", "title", "kind", "category", "galaxy", "summary", "mitre", "tags"].join(","),
  ...entities.map((entity) => [entity.id, entity.slug, entity.title, entity.kind, entity.category, entity.galaxyId, entity.summary, entity.mitre.join("|"), entity.tags.join("|")].map(csv).join(","))
].join("\n"));
fs.writeFileSync(path.join(output, "hugin-evidence.csv"), [
  ["evidence_id", "title", "topic", "summary", "quality_score", "related_entities"].join(","),
  ...evidence.map((item) => [
    item.evidenceId,
    item.title,
    item.topic,
    item.summary,
    item.qualityScore,
    item.relatedEntityIds.join("|")
  ].map(csv).join(","))
].join("\n"));

const xml = (value) => String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll('"', "&quot;");
fs.writeFileSync(path.join(output, "hugin.graphml"), `<?xml version="1.0" encoding="UTF-8"?>\n<graphml xmlns="http://graphml.graphdrawing.org/xmlns"><graph id="HUGIN" edgedefault="directed">${entities.map((entity) => `<node id="${xml(entity.id)}"><data key="title">${xml(entity.title)}</data><data key="kind">${xml(entity.kind)}</data><data key="galaxy">${xml(entity.galaxyId)}</data></node>`).join("")}${relations.map((edge) => `<edge id="${xml(edge.id)}" source="${xml(edge.source)}" target="${xml(edge.target)}"><data key="type">${xml(edge.type)}</data></edge>`).join("")}</graph></graphml>\n`);
fs.writeFileSync(path.join(output, "metrics.json"), `${JSON.stringify(manifest, null, 2)}\n`);

const files = fs.readdirSync(output).filter((name) => name !== "SHA256SUMS.txt").sort();
fs.writeFileSync(path.join(output, "SHA256SUMS.txt"), `${files.map((name) => `${crypto.createHash("sha256").update(fs.readFileSync(path.join(output, name))).digest("hex")}  ${name}`).join("\n")}\n`);
