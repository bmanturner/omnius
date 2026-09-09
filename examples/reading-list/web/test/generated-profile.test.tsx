import { createServiceQueryClient } from "@omnius/web-sdk/react";
import { createMemoryHistory } from "@tanstack/react-router";
import { render, screen } from "@testing-library/react";

import { App } from "../src/app";

describe("generated web application", () => {
  it("renders the application-owned not-found route", async () => {
    const history = createMemoryHistory({ initialEntries: ["/missing"] });
    const queryClient = createServiceQueryClient({
      defaultOptions: { queries: { retry: false } },
    });

    render(<App history={history} queryClient={queryClient} />);

    expect(await screen.findByRole("heading", { name: "Page not found" })).toBeTruthy();
  });
});
