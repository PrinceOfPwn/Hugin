import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";

const dist = path.resolve("dist");
const gzipSize = (file) => zlib.gzipSync(fs.readFileSync(file), { level: 9 }).length;
const failures = [];
const check = (label, file, limit) => {
  const size = gzipSize(file);
  console.log(`${label}: ${(size / 1024).toFixed(1)} KiB gzip / ${(limit / 1024).toFixed(0)} KiB budget`);
  if (size > limit) failures.push(`${label} exceeds budget`);
};

check("Dashboard HTML", path.join(dist, "index.html"), 100 * 1024);
const dataDir = path.join(dist, "data");
const files = fs.readdirSync(dataDir);
check("Graph base", path.join(dataDir, files.find((file) => file.startsWith("graph."))), 1024 * 1024);
check("Similarity", path.join(dataDir, files.find((file) => file.startsWith("similarity."))), 1536 * 1024);
for (const file of files.filter((name) => name.startsWith("content-"))) {
  if (gzipSize(path.join(dataDir, file)) > 200 * 1024) failures.push(`${file} exceeds 200 KiB gzip`);
}
if (failures.length) {
  console.error(failures.join("\n"));
  process.exit(1);
}
