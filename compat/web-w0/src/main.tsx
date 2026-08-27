import { createRoot } from "react-dom/client";

import { CompatibilityApp } from "./app";

const root = document.querySelector("#root");
if (!(root instanceof HTMLElement)) {
  throw new Error("W0 compatibility root is missing");
}

createRoot(root).render(<CompatibilityApp />);
