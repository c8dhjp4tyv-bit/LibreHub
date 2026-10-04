import { test, expect } from "@playwright/test";
// The mandatory M4 Python acceptance starts a real API and publishes this app first.
// No intercepted HTTP or mocked catalog data in this browser test.
test("discover a real published app and download its signed repository reference", async ({
  page,
}) => {
  const appId = process.env.LIBREHUB_E2E_APP_ID;
  if (!appId)
    throw new Error(
      "LIBREHUB_E2E_APP_ID must identify the real published acceptance application",
    );
  page.on("requestfailed", (request) => {
    if (request.resourceType() === "image")
      console.error("Image request failed:", request.url(), request.failure()?.errorText);
  });
  page.on("console", (message) => {
    if (message.type() === "error") console.error("Browser error:", message.text());
  });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Recently updated" }),
  ).toBeVisible();
  await expect(
    page
      .getByRole("navigation", { name: "Main navigation" })
      .getByRole("link", { name: "Explore" }),
  ).toBeVisible();
  await page.getByRole("textbox", { name: "Search applications" }).fill(appId);
  await page.getByRole("button", { name: /Search/ }).click();
  await expect(page).toHaveURL(/search\?q=/);
  await page.locator(`.app-card[href="/apps/${appId}"]`).click();
  await expect(page.getByRole("heading", { level: 1 })).toContainText(
    "Catalog Hello",
  );
  await expect(
    page.getByRole("heading", { name: "Application permissions" }),
  ).toBeVisible();
  await expect(page.getByText("Build commit", { exact: true })).toBeVisible();
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("link", { name: /Install with Flatpak/ }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe(`${appId}.flatpakref`);
  await page.keyboard.press("Tab");
  const screenshot = page.getByRole("img", { name: "Acceptance image" });
  console.log("Screenshot URL:", await screenshot.getAttribute("src"));
  await screenshot.scrollIntoViewIfNeeded();
  await expect
    .poll(
      () => screenshot.evaluate((image) => (image as HTMLImageElement).naturalWidth),
      { timeout: 20000 },
    )
    .toBeGreaterThan(0);
  await page.screenshot({
    path: "../../data/m4-store-mobile.png",
    fullPage: true,
  });
});
