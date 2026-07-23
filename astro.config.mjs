import { defineConfig } from "astro/config";
import react from "@astrojs/react";
import sitemap from "@astrojs/sitemap";

export default defineConfig({
  site: "https://princeofpwn.github.io",
  base: "/Hugin",
  output: "static",
  trailingSlash: "always",
  integrations: [react(), sitemap()],
  build: {
    assets: "_assets",
    inlineStylesheets: "auto"
  },
  vite: {
    build: {
      cssCodeSplit: true
    }
  }
});
