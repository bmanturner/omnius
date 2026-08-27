import { GENERATED_AGAINST_CONTRACT_HASH, NetworkRequestError, ServiceProblemError } from "@omnius/web-sdk/client";
import {
  SERVICE_QUERY_GC_TIME_MS,
  SERVICE_QUERY_STALE_TIME_MS,
  WebSdkProvider,
  createServiceQueryClient,
  shouldRetryServiceQuery,
  useClientConfiguration,
} from "@omnius/web-sdk/react";
import { useQueryClient } from "@tanstack/react-query";
import { createMemoryHistory } from "@tanstack/react-router";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import { App } from "../src/app";
import { BUILD_METADATA } from "../src/build-metadata";
import { parseReferenceRecordSearch } from "../src/router";
import { server } from "./setup";
import {
  createListReferenceRecordsHandler,
  createProblemDetailsFixture,
  createReferenceRecordFixture,
  createReferenceRecordPageFixture,
} from "./contract-mocks";

function ProviderProbe() {
  const configuration = useClientConfiguration();
  const queryClient = useQueryClient();
  return (
    <output>
      {configuration.baseUrl} · {String(queryClient.getDefaultOptions().mutations?.retry)}
    </output>
  );
}

function renderRecords(path = "/reference-records") {
  const history = createMemoryHistory({ initialEntries: [path] });
  const queryClient = createServiceQueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(<App history={history} queryClient={queryClient} />);
}

const referenceRecord = createReferenceRecordFixture({
  name: "Primary record",
  version: 3,
  updated_at: "2026-08-21T13:30:00Z",
});

describe("SDK React composition", () => {
  it("provides the configured client and query cache without global registration", () => {
    const queryClient = createServiceQueryClient();
    render(
      <WebSdkProvider configuration={{ baseUrl: "/api" }} queryClient={queryClient}>
        <ProviderProbe />
      </WebSdkProvider>,
    );

    expect(screen.getByText("/api · false")).toBeTruthy();
    expect(queryClient.getDefaultOptions().queries?.staleTime).toBe(SERVICE_QUERY_STALE_TIME_MS);
    expect(queryClient.getDefaultOptions().queries?.gcTime).toBe(SERVICE_QUERY_GC_TIME_MS);
    expect(queryClient.getDefaultOptions().queries?.refetchOnWindowFocus).toBe(true);
    expect(queryClient.getDefaultOptions().queries?.refetchOnReconnect).toBe(true);
  });

  it("retries transient normalized queries but not client problems or mutations", () => {
    expect(shouldRetryServiceQuery(0, new NetworkRequestError())).toBe(true);
    expect(shouldRetryServiceQuery(2, new NetworkRequestError())).toBe(false);
    const validationProblem = new ServiceProblemError(
      {
        status: 422,
        type: "urn:omnius:problem:validation",
        code: "VALIDATION_FAILED",
        title: "Validation failed",
        fieldViolations: [],
        retryable: true,
      },
      {},
    );
    expect(shouldRetryServiceQuery(0, validationProblem)).toBe(false);
    expect(createServiceQueryClient().getDefaultOptions().mutations?.retry).toBe(false);
  });
});

describe("reference record route", () => {
  it("shows an accessible loading state", async () => {
    server.use(createListReferenceRecordsHandler({ latency: "infinite" }));

    renderRecords();

    expect(
      await screen.findByRole("heading", { name: "Loading reference records" }),
    ).toBeTruthy();
  });

  it("renders success and keeps filters in the URL-owned request", async () => {
    server.use(
      createListReferenceRecordsHandler({
        response: {
          status: 200,
          body: createReferenceRecordPageFixture({
            items: [referenceRecord],
            next_cursor: "next-token",
          }),
        },
        inspectRequest(request) {
          const url = new URL(request.url);
          expect(url.searchParams.get("limit")).toBe("50");
          expect(url.searchParams.get("cursor")).toBe("opaque-token");
        },
      }),
    );

    renderRecords("/reference-records?limit=50&cursor=opaque-token");

    expect(await screen.findByText("Primary record")).toBeTruthy();
    expect(document.title).toBe("Reference records · Omnius");
    expect(screen.getByRole("link", { name: "Next page" })).toBeTruthy();
    expect(screen.getByRole("combobox")).toHaveProperty("value", "50");
  });

  it("renders a useful empty state", async () => {
    server.use(
      createListReferenceRecordsHandler({
        response: {
          status: 200,
          body: createReferenceRecordPageFixture({ items: [], next_cursor: "" }),
        },
      }),
    );

    renderRecords();

    expect(await screen.findByRole("heading", { name: "No reference records yet" })).toBeTruthy();
  });

  it("renders normalized problem detail and request ID", async () => {
    server.use(
      createListReferenceRecordsHandler({
        response: {
          status: 503,
          body: createProblemDetailsFixture({
            detail: "Try again shortly.",
            request_id: "req-test-503",
          }),
        },
      }),
    );

    renderRecords();

    expect((await screen.findByRole("alert")).textContent).toContain("Try again shortly.");
    expect(screen.getByText("req-test-503")).toBeTruthy();
  });

  it("updates the page-size search parameter instead of local record state", async () => {
    server.use(
      createListReferenceRecordsHandler({
        response: {
          status: 200,
          body: createReferenceRecordPageFixture({ items: [], next_cursor: "" }),
        },
      }),
    );
    const history = createMemoryHistory({ initialEntries: ["/reference-records?limit=25"] });
    render(
      <App
        history={history}
        queryClient={createServiceQueryClient({ defaultOptions: { queries: { retry: false } } })}
      />,
    );
    await screen.findByRole("heading", { name: "No reference records yet" });

    fireEvent.change(screen.getByRole("combobox"), { target: { value: "100" } });

    await waitFor(() => {
      expect(history.location.search).toContain("limit=100");
    });
  });
});

describe("routing and build identity", () => {
  it("normalizes record search input at the router boundary", () => {
    expect(parseReferenceRecordSearch({ limit: "50", cursor: "opaque" })).toEqual({
      limit: 50,
      cursor: "opaque",
    });
    expect(parseReferenceRecordSearch({ limit: "9", cursor: "" })).toEqual({ limit: 25 });
  });

  it("displays the generated contract hash in the shell", async () => {
    server.use(
      createListReferenceRecordsHandler({
        response: {
          status: 200,
          body: createReferenceRecordPageFixture({ items: [], next_cursor: "" }),
        },
      }),
    );
    renderRecords();

    expect(await screen.findByText(GENERATED_AGAINST_CONTRACT_HASH)).toBeTruthy();
    expect(BUILD_METADATA.contractHash).toBe(GENERATED_AGAINST_CONTRACT_HASH);
  });

  it("surfaces a runtime contract mismatch from the client callback", async () => {
    const runtimeHash = `sha256:${"a".repeat(64)}`;
    server.use(
      createListReferenceRecordsHandler({
        response: {
          status: 200,
          body: createReferenceRecordPageFixture({ items: [], next_cursor: "" }),
        },
        headers: { "X-Omnius-Contract-Hash": runtimeHash },
      }),
    );
    renderRecords();

    const banner = await screen.findByRole("alert", { name: "Contract mismatch" });
    expect(banner.textContent).toContain(runtimeHash);
    expect(banner.textContent).toContain(GENERATED_AGAINST_CONTRACT_HASH);
  });

  it("renders the typed not-found route", async () => {
    renderRecords("/missing-route");
    expect(await screen.findByRole("heading", { name: "Page not found" })).toBeTruthy();
  });
});
