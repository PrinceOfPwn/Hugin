import { expect, test } from "@playwright/test";

test("dashboard exposes the complete dataset", async ({ page }) => {
  await page.goto("./");
  await expect(page.getByRole("heading", { name: /Map the machinery/ })).toBeVisible();
  await expect(page.getByText("5,608").first()).toBeVisible();
});

test("catalog filters and preserves a shareable URL", async ({ page }) => {
  await page.goto("./explore/");
  await page.getByLabel("Filter catalog").fill("Recycled Gate");
  await expect(page.getByRole("heading", { name: /Recycled Gate/i }).first()).toBeVisible();
  await expect(page).toHaveURL(/q=Recycled\+Gate/);
});

test("graph renders and links to the accessible catalog", async ({ page }) => {
  await page.goto("./graph/");
  await expect(page.getByRole("img", { name: /5,608 HUGIN entities/ })).toBeVisible();
  await expect(page.getByRole("link", { name: /accessible catalog/i })).toBeVisible();
});

test("deep entity routes survive the GitHub Pages base path", async ({ page }) => {
  await page.goto("./explore/?q=Recycled+Gate");
  await page.getByRole("heading", { name: /Recycled Gate/i }).first().click();
  await expect(page.locator("article[data-pagefind-body]")).toBeVisible();
  await expect(page).toHaveURL(/\/Hugin\/techniques\//);
});
