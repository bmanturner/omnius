import { render, screen } from "@testing-library/react";
import { HttpResponse, http } from "msw";
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { CompatibilityApp } from "./app";
import { compatibilitySchema } from "./compatibility";

const server = setupServer(
  http.get("http://localhost/problem", () =>
    HttpResponse.json(
      {
        type: "https://example.invalid/problems/conflict",
        title: "Conflict",
        status: 409,
      },
      {
        status: 409,
        headers: { "x-request-id": "req-w0" },
      },
    ),
  ),
);

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe("pinned frontend graph", () => {
  it("renders React through Query and Router providers", async () => {
    render(<CompatibilityApp />);
    expect(
      await screen.findByText("Omnius web compatibility fixture"),
    ).toBeTruthy();
  });

  it("uses Zod and MSW with problem response metadata", async () => {
    expect(compatibilitySchema.parse({ name: "compatible" })).toEqual({
      name: "compatible",
    });
    const response = await fetch("http://localhost/problem");
    expect([response.status, response.headers.get("x-request-id")]).toEqual([
      409,
      "req-w0",
    ]);
  });
});
