import { expect, test } from "@playwright/test";

test("dashboard presents the curated knowledge layer", async ({ page }) => {
  await page.goto("./");
  await expect(page.getByRole("heading", { name: /Map tradecraft/i })).toBeVisible();
  await expect(page.getByText("1,845").first()).toBeVisible();
  await expect(page.getByText(/anonymous evidence records/i)).toBeVisible();
});

test("catalog filters and preserves a shareable URL", async ({ page }) => {
  await page.goto("./explore/");
  await page.getByLabel("Filter catalog").fill("Recycled Gate");
  await expect(page.getByRole("heading", { name: /Recycled Gate/i }).first()).toBeVisible();
  await expect(page).toHaveURL(/q=Recycled\+Gate/);
  await expect(page.getByText(/title slide/i)).toHaveCount(0);
});

test("graph exposes structured modes and an accessible catalog", async ({ page }) => {
  await page.goto("./graph/");
  await expect(page.getByRole("img", { name: /1,845 HUGIN knowledge nodes/i })).toBeVisible();
  await expect(page.getByLabel("Graph view controls")).toBeVisible();
  await expect(page.getByRole("link", { name: /accessible catalog/i })).toBeVisible();
});

test("deep entity routes stay readable under the GitHub Pages base path", async ({ page }) => {
  await page.goto("./explore/?q=Recycled+Gate");
  await page.getByRole("heading", { name: /Recycled Gate/i }).first().click();
  await expect(page.locator("[data-pagefind-body]")).toBeVisible();
  await expect(page.getByRole("heading", { name: /What this record contributes/i })).toBeVisible();
  await expect(page).toHaveURL(/\/Hugin\/techniques\//);
});

test("quality report exposes the quarantine", async ({ page }) => {
  await page.goto("./quality/");
  await expect(page.getByRole("heading", { name: /Only useful knowledge/i })).toBeVisible();
  await expect(page.getByText("190").first()).toBeVisible();
  await expect(page.getByText(/title or cover/i)).toBeVisible();
});
