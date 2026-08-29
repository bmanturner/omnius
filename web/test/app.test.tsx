import { GENERATED_AGAINST_CONTRACT_HASH, NetworkRequestError, ServiceProblemError, serviceHttp } from "@omnius/web-sdk/client";
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
import { http, HttpResponse } from "msw";

import { App } from "../src/app";
import { BUILD_METADATA } from "../src/build-metadata";
import { createAppRouter, parseReferenceRecordSearch } from "../src/router";
import { server } from "./setup";
import {
  createListReferenceRecordsHandler,
  createProblemDetailsFixture,
  createReferenceRecordFixture,
  createReferenceRecordPageFixture,
} from "./contract-mocks";
import type { ProblemDetailsFixture } from "./contract-mocks";

function ProviderProbe() {
  const configuration = useClientConfiguration();
  const queryClient = useQueryClient();
  return (
    <output>
      {configuration.baseUrl} · {String(queryClient.getDefaultOptions().mutations?.retry)}
    </output>
  );
}

function renderRecords(path = "/records") {
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
          expect(url.searchParams.get("name")).toBe("Primary");
        },
      }),
    );

    renderRecords("/records?limit=50&cursor=opaque-token&name=Primary");

    expect(await screen.findByText("Primary record", { selector: ".record-name" })).toBeTruthy();
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
    const history = createMemoryHistory({ initialEntries: ["/records?limit=25"] });
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

  it("maps authoritative server field violations to the accessible create control", async () => {
    server.use(
      createListReferenceRecordsHandler({
        response: {
          status: 200,
          body: createReferenceRecordPageFixture({ items: [referenceRecord], next_cursor: "" }),
        },
      }),
      http.post("/reference-records", () =>
        HttpResponse.json(
          createProblemDetailsFixture({
            status: 422,
            code: "VALIDATION_FAILED",
            title: "Validation failed",
            detail: "request body validation failed",
            request_id: "req-form-422",
            errors: [
              {
                pointer: "/name",
                code: "invalid",
                message: "Enter a name between 1 and 100 characters.",
              },
            ],
          }),
          {
            status: 422,
            headers: { "Content-Type": "application/problem+json" },
          },
        ),
      ),
    );
    renderRecords();
    await screen.findByText("Primary record", { selector: ".record-name" });

    fireEvent.change(screen.getByLabelText("Name", { selector: "#create-reference-record-name" }), {
      target: { value: "   " },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create record" }));

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Validation failed");
    expect(alert.textContent).toContain("req-form-422");
    expect(
      screen.getByText("Enter a name between 1 and 100 characters.", {
        selector: ".field-error",
      }),
    ).toBeTruthy();
    expect(
      screen
        .getByLabelText("Name", { selector: "#create-reference-record-name" })
        .getAttribute("aria-invalid"),
    ).toBe("true");
  });

  it("keeps the attempted edit and retries with the refreshed version after a 412", async () => {
    let updateAttempts = 0;
    server.use(
      createListReferenceRecordsHandler({
        response: {
          status: 200,
          body: createReferenceRecordPageFixture({ items: [referenceRecord], next_cursor: "" }),
        },
      }),
      http.get("/reference-records/:id", () =>
        HttpResponse.json({ ...referenceRecord, name: "Server name", version: 4 }),
      ),
      http.put("/reference-records/:id", async ({ request }) => {
        updateAttempts += 1;
        if (updateAttempts === 1) {
          return HttpResponse.json(
            createProblemDetailsFixture({
              status: 412,
              code: "PRECONDITION_FAILED",
              title: "Precondition failed",
              request_id: "req-conflict-412",
            }),
            {
              status: 412,
              headers: { "Content-Type": "application/problem+json" },
            },
          );
        }
        expect(request.headers.get("if-match")).toBe('\"v4\"');
        expect(await request.json()).toEqual({ name: "My retained edit" });
        return HttpResponse.json({ ...referenceRecord, name: "My retained edit", version: 5 });
      }),
    );
    renderRecords();
    await screen.findByText("Primary record", { selector: ".record-name" });

    fireEvent.click(screen.getByRole("button", { name: "Edit Primary record" }));
    fireEvent.change(screen.getByLabelText("Name", { selector: "#edit-reference-record-name" }), {
      target: { value: "My retained edit" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

    const conflictAlert = await screen.findByRole("alert");
    expect(conflictAlert.textContent).toContain("HTTP 412");
    expect(conflictAlert.textContent).toContain("req-conflict-412");
    fireEvent.click(screen.getByRole("button", { name: "Keep my name and retry" }));

    await waitFor(() => {
      expect(updateAttempts).toBe(2);
    });
  });
});

describe("routing and build identity", () => {
  it("normalizes record search input at the router boundary", () => {
    expect(
      parseReferenceRecordSearch({
        limit: "50",
        cursor: "opaque",
        name: "  Primary  ",
      }),
    ).toEqual({
      limit: 50,
      cursor: "opaque",
      name: "Primary",
    });
    expect(
      parseReferenceRecordSearch({
        limit: "9",
        cursor: "",
        name: "x".repeat(101),
      }),
    ).toEqual({ limit: 25 });
    expect(
      parseReferenceRecordSearch({
        limit: 25,
        name: ` ${"😀".repeat(100)} `,
      }),
    ).toEqual({ limit: 25, name: "😀".repeat(100) });
    expect(
      parseReferenceRecordSearch({
        limit: 25,
        name: "😀".repeat(101),
      }),
    ).toEqual({ limit: 25 });
  });

  it("builds root and nested deployment links from the public base", () => {
    const rootRouter = createAppRouter(createMemoryHistory(), "/");
    const nestedRouter = createAppRouter(createMemoryHistory(), "/console/");

    expect(rootRouter.buildLocation({ to: "/records", search: { limit: 25 } }).href).toBe(
      "/records?limit=25",
    );
    expect(
      nestedRouter.buildLocation({ to: "/records", search: { limit: 25 } }).href,
    ).toBe("/console/records?limit=25");
    expect(nestedRouter.basepath).toBe("/console");
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

describe("account route", () => {
  it("keeps root authentication transport under a nested router base", async () => {
    const problemResponse = (body: ProblemDetailsFixture) =>
      HttpResponse.json(body, {
        status: 401,
        headers: { "Content-Type": "application/problem+json" },
      });
    server.use(
      http.get(serviceHttp.getGetCurrentPrincipalUrl(), ({ request }) => {
        expect(new URL(request.url).pathname).toBe("/whoami");
        return problemResponse(
          createProblemDetailsFixture({
            status: 401,
            code: "AUTHENTICATION_REQUIRED",
            title: "Authentication required",
          }),
        );
      }),
      http.post("/auth/login", async ({ request }) => {
        expect(new URL(request.url).pathname).toBe("/auth/login");
        expect(await request.json()).toEqual({
          identifier: "person@example.test",
          password: "incorrect password",
        });
        return problemResponse(
          createProblemDetailsFixture({
            status: 401,
            code: "INVALID_CREDENTIALS",
            title: "Invalid credentials",
          }),
        );
      }),
    );
    const history = createMemoryHistory({ initialEntries: ["/console/account"] });
    render(
      <App
        history={history}
        publicBasePath="/console"
        queryClient={createServiceQueryClient({ defaultOptions: { queries: { retry: false } } })}
      />,
    );

    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Email"), {
      target: { value: "person@example.test" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "incorrect password" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));

    expect((await screen.findByRole("alert")).textContent).toContain("Invalid credentials");
  });
});

const authenticatedSession: serviceHttp.BrowserSessionResponseSchema = {
  assurance: "aal1",
  auth_method: "password",
  authenticated_at: "2026-08-28T10:00:00Z",
  expires_at: "2026-08-28T18:00:00Z",
  kind: "user",
  presentation_permissions: [],
  resource_permissions: [],
  scopes: [],
  subject_id: "018f7777-7777-7777-8777-777777777777",
  tenant: null,
  tenant_id: null,
};

describe("account lifecycle surfaces", () => {
  it("consumes an email verification fragment once without browser storage", async () => {
    let submittedToken: string | undefined;
    server.use(
      http.post(serviceHttp.getCompleteEmailVerificationUrl(), async ({ request }) => {
        const body = await request.json() as serviceHttp.AccountTokenCompletionRequestSchema;
        submittedToken = body.token;
        return new HttpResponse(null, { status: 204 });
      }),
    );
    window.history.replaceState(null, "", "/verify-email#token=verification-secret");
    const history = createMemoryHistory({ initialEntries: ["/verify-email"] });
    render(<App history={history} queryClient={createServiceQueryClient()} />);

    expect(await screen.findByRole("heading", { name: "Email verified" })).toBeTruthy();
    expect(submittedToken).toBe("verification-secret");
    expect(window.location.hash).toBe("");
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
    expect(document.body.textContent).not.toContain("verification-secret");
  });

  it("renders typed consent metadata and a native decision form", async () => {
    server.use(
      http.get(serviceHttp.getGetCurrentPrincipalUrl(), () => HttpResponse.json(authenticatedSession)),
      http.get(serviceHttp.getOauthAuthorizeInteractionUrl({ request: "opaque-request" }), ({ request }) => {
        expect(new URL(request.url).searchParams.get("request")).toBe("opaque-request");
        const interaction: serviceHttp.OAuthAuthorizationInteractionSchema = {
          client_name: "Example client",
          client_origin: "https://client.example",
          minimum_assurance: "aal1",
          redirect_host: "client.example",
          requirement: "consent",
          resource: "https://api.example",
          resource_description: "Read data from the API.",
          resource_name: "Example API",
          scopes: [{ name: "records:read", description: "Read records", newly_requested: true }],
        };
        return HttpResponse.json(interaction);
      }),
    );
    const history = createMemoryHistory({ initialEntries: ["/authorize?request=opaque-request"] });
    const { container } = render(<App history={history} queryClient={createServiceQueryClient()} />);

    expect(await screen.findByRole("heading", { name: "Allow Example client to connect?" })).toBeTruthy();
    const form = container.querySelector<HTMLFormElement>('form[action="/oauth/authorize/decision"]');
    expect(form).not.toBeNull();
    expect(form?.method).toBe("post");
    expect(form?.querySelector<HTMLInputElement>('input[name="request"]')?.value).toBe("opaque-request");
    expect(form?.querySelectorAll("[name]").length).toBe(3);
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
  });
});
