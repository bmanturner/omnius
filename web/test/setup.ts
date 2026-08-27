import { cleanup } from "@testing-library/react";
import { setupServer } from "msw/node";
import { createContractMockHandlers } from "./contract-mocks";

export const server = setupServer(...createContractMockHandlers());
Object.defineProperty(window, "scrollTo", {
  configurable: true,
  value: vi.fn(),
});

beforeAll(() => {
  server.listen({ onUnhandledRequest: "error" });
});

afterEach(() => {
  cleanup();
  server.resetHandlers();
});

afterAll(() => {
  server.close();
});
