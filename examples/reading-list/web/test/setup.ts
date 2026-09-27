import { cleanup } from "@testing-library/react";
import { setupServer } from "msw/node";

import { defaultHandlers } from "./mock-api";

export const server = setupServer(...defaultHandlers());

Object.defineProperty(globalThis, "BroadcastChannel", {
  configurable: true,
  value: undefined,
});

Object.defineProperty(window, "scrollTo", {
  configurable: true,
  value: vi.fn(),
});

if (typeof HTMLDialogElement !== "undefined") {
  Object.defineProperties(HTMLDialogElement.prototype, {
    showModal: {
      configurable: true,
      value(this: HTMLDialogElement) {
        this.setAttribute("open", "");
      },
    },
    close: {
      configurable: true,
      value(this: HTMLDialogElement) {
        this.removeAttribute("open");
        this.dispatchEvent(new Event("close"));
      },
    },
  });
}

beforeAll(() => {
  server.listen({ onUnhandledRequest: "error" });
});

afterEach(() => {
  cleanup();
  server.resetHandlers();
  window.localStorage.clear();
  window.sessionStorage.clear();
  window.history.replaceState(null, "", "/");
});

afterAll(() => {
  server.close();
});
