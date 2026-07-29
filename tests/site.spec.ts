import { expect, test } from "@playwright/test";

test("dashboard presents the curated knowledge layer", async ({ page }) => {
  await page.goto("./");
  await expect(page.getByRole("heading", { name: /Map tradecraft/i })).toBeVisible();
  await expect(page.getByText(/knowledge nodes/i).first()).toBeVisible();
  await expect(page.getByText(/evidence records/i).first()).toBeVisible();
});

test("catalog filters and preserves a shareable URL", async ({ page }) => {
  await page.goto("./explore/");
  await page.getByLabel("Search catalog").fill("Recycled Gate");
  await expect(page.getByRole("heading", { name: /Recycled Gate/i }).first()).toBeVisible();
  await expect(page).toHaveURL(/q=Recycled\+Gate/);
  await expect(page.getByText(/title slide/i)).toHaveCount(0);
});

test("graph exposes structured modes and an accessible catalog", async ({ page }) => {
  await page.goto("./graph/");
  await expect(page.getByRole("img", { name: /HUGIN knowledge nodes/i })).toBeVisible();
  await expect(page.getByLabel("Graph view controls")).toBeVisible();
  await expect(page.getByRole("link", { name: /accessible catalog/i })).toBeVisible();
});

test("deep entity routes stay readable under the GitHub Pages base path", async ({ page }) => {
  await page.goto("./explore/");
  await page.getByLabel("Search catalog").fill("Recycled Gate");
  await expect(page).toHaveURL(/q=Recycled\+Gate/);
  await page.getByRole("option", { name: /Recycled Gate/i }).first().click();
  await page.getByRole("link", { name: /Open full record/i }).click();
  await expect(page).toHaveURL(/\/Hugin\/techniques\//);
  await expect(page.locator("[data-pagefind-body]")).toBeVisible();
  await expect(page.getByRole("heading", { name: /What this record contributes/i })).toBeVisible();
});

test("quality report exposes the quarantine", async ({ page }) => {
  await page.goto("./quality/");
  await expect(page.getByRole("heading", { name: /Only useful knowledge/i })).toBeVisible();
  await expect(page.getByText(/title or cover/i)).toBeVisible();
});

test("MITRE matrix preserves exact sub-techniques and official links", async ({ page }) => {
  await page.goto("./mitre/");
  await expect(page.getByRole("heading", { name: /MITRE matrix/i })).toBeVisible();
  await expect(page.getByText(/exact techniques represented/i)).toBeVisible();

  const search = page.getByLabel("Search MITRE ID");
  await search.fill("T1055.004");
  await search.press("Enter");

  const technique = page.locator('[data-mitre-id="T1055.004"]').first();
  await expect(technique).toBeVisible();
  await expect(technique.getByText("Asynchronous Procedure Call")).toBeVisible();
  await expect(technique.getByRole("button")).toHaveAttribute("aria-expanded", "true");
  await expect(
    technique.getByRole("link", { name: /View T1055\.004 on attack\.mitre\.org/i }),
  ).toHaveAttribute("href", "https://attack.mitre.org/techniques/T1055/004/");
});
