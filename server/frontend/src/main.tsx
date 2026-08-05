import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router";
import App from "./App";
import { applyTheme, getStoredTheme } from "./lib/theme";
import { applyAccent, getStoredAccent } from "./lib/accent";
import "./styles.css";

// Applied before the first render so there's no flash of the wrong
// theme/accent.
applyTheme(getStoredTheme());
applyAccent(getStoredAccent());

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>
);
