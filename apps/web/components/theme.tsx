"use client";
import { useState, useEffect } from "react";
export function ThemeToggle() {
  const [theme, setTheme] = useState("system");
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);
  return (
    <label className="theme-select">
      <span className="sr-only">Color theme</span>
      <select
        value={theme}
        onChange={(e) => setTheme(e.target.value)}
        aria-label="Color theme"
      >
        <option value="system">System theme</option>
        <option value="light">Light</option>
        <option value="dark">Dark</option>
      </select>
    </label>
  );
}
