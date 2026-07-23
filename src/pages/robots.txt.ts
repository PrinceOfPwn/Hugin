export function GET() {
  return new Response("User-agent: *\nAllow: /\nSitemap: https://princeofpwn.github.io/Hugin/sitemap-index.xml\n", { headers: { "Content-Type": "text/plain" } });
}
