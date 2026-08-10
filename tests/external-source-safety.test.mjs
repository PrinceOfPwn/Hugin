import assert from "node:assert/strict";
import crypto from "node:crypto";
import { sha256Bytes } from "../scripts/lib/binary-hash.mjs";
import { assertPublicHttpUrl, isPublicIp } from "../scripts/lib/public-url.mjs";

assert.equal(sha256Bytes(Buffer.from([0xff, 0x00, 0x61])), crypto.createHash("sha256").update(Buffer.from([0xff, 0x00, 0x61])).digest("hex"));
assert.notEqual(sha256Bytes(Buffer.from([0xff, 0x00, 0x61])), crypto.createHash("sha256").update(String(Buffer.from([0xff, 0x00, 0x61]))).digest("hex"));

for (const address of ["127.0.0.1", "10.0.0.1", "169.254.1.1", "172.16.0.1", "192.168.1.1", "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1"]) {
  assert.equal(isPublicIp(address), false, `${address} must be rejected as non-public`);
}
for (const address of ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"]) {
  assert.equal(isPublicIp(address), true, `${address} should be treated as public`);
}

await assert.rejects(() => assertPublicHttpUrl("http://127.0.0.1/test"), /non-public/);
await assert.rejects(() => assertPublicHttpUrl("http://localhost/test"), /public/);
await assert.rejects(() => assertPublicHttpUrl("file:///tmp/a.pdf"), /http\(s\)/);
await assert.doesNotReject(() => assertPublicHttpUrl("https://1.1.1.1/test"));

console.log("[external-source-safety] public-only URL and byte-hash contracts — OK");
