import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router";
import App from "./App";
import { applyTheme, getStoredTheme } from "./lib/theme";
import { applyAccent, getStoredAccent } from "./lib/accent";
import { applyLayoutWidth, getStoredLayoutWidth } from "./lib/layoutWidth";
import "./styles.css";

// Applied before the first render so there's no flash of the wrong
// theme/accent - and, for the layout width, no visible reflow from a
// 1600px column to a full-width one after the first paint.
applyTheme(getStoredTheme());
applyAccent(getStoredAccent());
applyLayoutWidth(getStoredLayoutWidth());

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>
);
