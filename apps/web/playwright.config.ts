import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "tests/e2e",
  workers: 1,
  retries: 0,
  use: {
    baseURL: process.env.LIBREHUB_WEB_PUBLIC_URL || "http://127.0.0.1:3000",
  },
  reporter: "list",
});
