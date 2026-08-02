import { useState } from "react";
import { applyTheme, getStoredTheme, Theme } from "../lib/theme";

export default function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(getStoredTheme);

  function toggle() {
    const next: Theme = theme === "dark" ? "light" : "dark";
    applyTheme(next);
    setTheme(next);
  }

  return (
    <button className="theme-toggle" onClick={toggle} title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}>
      {theme === "dark" ? "☀️" : "🌙"}
    </button>
  );
}
