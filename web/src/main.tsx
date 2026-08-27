import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./app";
import "./styles.css";

const container = document.querySelector<HTMLElement>("#root");
if (container === null) {
  throw new Error("The Omnius web root element is missing.");
}

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
