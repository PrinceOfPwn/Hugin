import fs from "node:fs";
import path from "node:path";

const root = path.resolve("dist");
const errors = [];
const readable = new Set([".html", ".json", ".js", ".css", ".xml", ".txt", ".svg"]);
const forbidden = [
  { label: "removed copy", pattern: /Nothing disappears because it lacks an original relation/i },
  // Keep this uppercase-only so ordinary CSS values such as `sans-serif`
  // do not trigger the provider-name privacy gate.
  { label: "named training provider", pattern: /\bSANS(?:\s+Institute)?\b/ },
  { label: "course identifier", pattern: /\bSEC\d{3}(?:\.\d+)?\b/i },
  { label: "named research course", pattern: /\bCRTO\b|\bCertified\s+Red\s+Team\s+Operator\b/i },
  { label: "named development course", pattern: /MalDev/i },
  { label: "named training provider", pattern: /OffSec|\bOffensive\s+Security\b/i },
  { label: "local username", pattern: /\b(?:emiperalta|tamarisk)\b/i },
  { label: "absolute owner path", pattern: /\/(?:Users|home)\/(?:emiperalta|tamarisk|source-owner)(?:\/|\\)/i },
  { label: "absolute Windows user path", pattern: /[A-Za-z]:(?:\\+|\/+)(?:Users|home)(?:\\+|\/+)/i }
];

function walk(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const target = path.join(directory, entry.name);
    return entry.isDirectory() ? walk(target) : [target];
  });
}

if (!fs.existsSync(root)) {
  throw new Error("Missing dist/. Run the site build first.");
}

for (const file of walk(root)) {
  if (!readable.has(path.extname(file))) continue;
  const text = fs.readFileSync(file, "utf8");
  for (const rule of forbidden) {
    if (rule.pattern.test(text)) {
      errors.push(`${path.relative(root, file)} contains forbidden ${rule.label}`);
    }
  }
}

if (fs.existsSync(path.join(root, "atlas"))) {
  errors.push("Raw Atlas reference routes must not be generated");
}

if (errors.length) {
  console.error(errors.map((error) => `- ${error}`).join("\n"));
  process.exit(1);
}

console.log("Public artifact is anonymous and contains no raw evidence routes.");
