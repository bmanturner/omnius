import { serviceHttp } from "@omnius/web-sdk/client";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, delay, http } from "msw";

import {
  authenticatedPrincipal,
  authenticatedPrincipalHandler,
  listReadingItemsHandler,
  problemResponse,
  readingItem,
} from "./mock-api";
import {
  createTestQueryClient,
  readingItemsQueryKey,
  renderApp,
} from "./render-app";
import { server } from "./setup";

function renderAuthenticated(items = [readingItem()]) {
  server.use(authenticatedPrincipalHandler(), listReadingItemsHandler(items));
  return renderApp("/");
}

describe("reading-list query states", () => {
  it("renders a deterministic loading state and then the empty state", async () => {
    server.use(
      authenticatedPrincipalHandler(),
      http.get(serviceHttp.getListReadingItemsUrl(), async () => {
        await delay(200);
        return HttpResponse.json([]);
      }),
    );
    renderApp("/");

    expect(await screen.findByRole("heading", { name: "Loading your reading list" })).toBeTruthy();
    expect(await screen.findByRole("heading", { name: "Your list is empty" })).toBeTruthy();
    expect(screen.getByText("0 of 500")).toBeTruthy();
  });

  it("renders linked items with a non-color-only finished state", async () => {
    renderAuthenticated([
      readingItem({ title: "First article" }),
      readingItem({
        id: "018f9999-9999-7999-8999-999999999999",
        title: "Finished essay",
        url: "https://example.test/essay",
        finished: true,
        version: 8,
      }),
    ]);

    const link = await screen.findByRole("link", { name: /First article/ });
    expect(link.getAttribute("href")).toBe("https://example.test/article");
    expect(screen.getByText("Not finished")).toBeTruthy();
    expect(screen.getByText("Finished")).toBeTruthy();
    expect(screen.getByText("2 of 500")).toBeTruthy();
  });

  it("presents an RFC 9457 service error and an explicit retry action", async () => {
    server.use(
      authenticatedPrincipalHandler(),
      http.get(serviceHttp.getListReadingItemsUrl(), () =>
        problemResponse(503, "Reading store unavailable", "READING_STORE_UNAVAILABLE"),
      ),
    );
    renderApp("/");

    expect(await screen.findByRole("heading", { name: "Reading store unavailable" })).toBeTruthy();
    expect(screen.getByText(/Request ID:/).textContent).toContain("req-503");
    expect(screen.getByRole("button", { name: "Try again" })).toBeTruthy();
  });
});

describe("reading-list mutations", () => {
  it("creates with a trimmed title and canonical URL through the generated operation", async () => {
    let items: serviceHttp.ReadingItem[] = [];
    server.use(
      authenticatedPrincipalHandler(),
      http.get(serviceHttp.getListReadingItemsUrl(), () => HttpResponse.json(items)),
      http.post(serviceHttp.getCreateReadingItemUrl(), async ({ request }) => {
        expect(await request.json()).toEqual({
          title: "Normalized title",
          url: "https://example.test/path",
        });
        const created = readingItem({ title: "Normalized title", url: "https://example.test/path" });
        items = [created];
        return HttpResponse.json(created, { status: 201 });
      }),
    );
    const user = userEvent.setup();
    renderApp("/");
    await screen.findByRole("heading", { name: "Your list is empty" });

    await user.type(screen.getByLabelText("Title"), "  Normalized title  ");
    await user.type(screen.getByLabelText("Web address"), "HTTPS://Example.Test/path");
    await user.click(screen.getByRole("button", { name: "Add to list" }));

    expect(await screen.findByText("Reading item added.")).toBeTruthy();
    expect(await screen.findByRole("link", { name: /Normalized title/ })).toBeTruthy();
    expect(document.activeElement).toBe(screen.getByLabelText("Title"));
  });

  it("toggles with the exact strong version precondition and refreshes the list", async () => {
    let current = readingItem({ version: 3, finished: false });
    let listRequests = 0;
    server.use(
      authenticatedPrincipalHandler(),
      http.get(serviceHttp.getListReadingItemsUrl(), () => {
        listRequests += 1;
        return HttpResponse.json([current]);
      }),
      http.patch(serviceHttp.getUpdateReadingItemUrl(current.id), async ({ request }) => {
        expect(request.headers.get("If-Match")).toBe('"v3"');
        expect(await request.json()).toEqual({ finished: true });
        current = readingItem({ version: 4, finished: true });
        return HttpResponse.json(current);
      }),
    );
    const user = userEvent.setup();
    renderApp("/");

    await user.click(await screen.findByRole("button", { name: "Mark as finished: A useful article" }));

    expect(await screen.findByText("Marked as finished.")).toBeTruthy();
    await waitFor(() => expect(listRequests).toBeGreaterThan(1));
    expect(screen.getByText("Finished")).toBeTruthy();
  });

  it("gives the delete dialog safe initial focus, restores it on cancel, and focuses the list after success", async () => {
    let items = [readingItem({ version: 6 })];
    server.use(
      authenticatedPrincipalHandler(),
      http.get(serviceHttp.getListReadingItemsUrl(), () => HttpResponse.json(items)),
      http.delete(serviceHttp.getDeleteReadingItemUrl(items[0]!.id), ({ request }) => {
        expect(request.headers.get("If-Match")).toBe('"v6"');
        items = [];
        return new HttpResponse(null, { status: 204 });
      }),
    );
    const user = userEvent.setup();
    renderApp("/");
    const trigger = await screen.findByRole("button", { name: "Delete A useful article" });

    await user.click(trigger);
    expect(await screen.findByRole("heading", { name: "Delete this item?" })).toBeTruthy();
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("button", { name: "Keep item" })));
    await user.click(screen.getByRole("button", { name: "Keep item" }));
    expect(document.activeElement).toBe(trigger);

    await user.click(trigger);
    await user.click(screen.getByRole("button", { name: "Delete item" }));
    expect(await screen.findByText("Deleted A useful article.")).toBeTruthy();
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("heading", { name: "Saved items" })));
    expect(await screen.findByRole("heading", { name: "Your list is empty" })).toBeTruthy();
  });

  it.each([
    { status: 412, action: "toggle" as const },
    { status: 428, action: "delete" as const },
  ])("refreshes without overwriting after a $status $action conflict", async ({ status, action }) => {
    const stale = readingItem({ version: 3, title: "Stale title" });
    const latest = readingItem({ version: 4, title: "Latest title", finished: false });
    let listRequests = 0;
    server.use(
      authenticatedPrincipalHandler(),
      http.get(serviceHttp.getListReadingItemsUrl(), () => {
        listRequests += 1;
        return HttpResponse.json([listRequests === 1 ? stale : latest]);
      }),
      http.patch(serviceHttp.getUpdateReadingItemUrl(stale.id), () =>
        problemResponse(status, "Precondition failed", "PRECONDITION_FAILED"),
      ),
      http.delete(serviceHttp.getDeleteReadingItemUrl(stale.id), () =>
        problemResponse(status, "Precondition required", "PRECONDITION_REQUIRED"),
      ),
    );
    const user = userEvent.setup();
    renderApp("/");
    await screen.findByRole("link", { name: /Stale title/ });

    if (action === "toggle") {
      await user.click(screen.getByRole("button", { name: "Mark as finished: Stale title" }));
    } else {
      await user.click(screen.getByRole("button", { name: "Delete Stale title" }));
      await user.click(screen.getByRole("button", { name: "Delete item" }));
    }

    expect(await screen.findByRole("heading", { name: "Your list was refreshed" })).toBeTruthy();
    expect(screen.getByText(/review the latest version before trying again/i)).toBeTruthy();
    expect(await screen.findByRole("link", { name: /Latest title/ })).toBeTruthy();
    expect(screen.queryByText("Finished")).toBeNull();
    expect(listRequests).toBeGreaterThan(1);
    if (action === "delete") {
      await waitFor(() =>
        expect(document.activeElement).toBe(
          screen.getByRole("heading", { name: "Saved items" }),
        ),
      );
    }
  });

  it("does not carry a failed delete error into the next confirmation", async () => {
    const first = readingItem({ title: "First item" });
    const second = readingItem({
      id: "018f9999-9999-7999-8999-999999999999",
      title: "Second item",
    });
    server.use(
      authenticatedPrincipalHandler(),
      listReadingItemsHandler([first, second]),
      http.delete(serviceHttp.getDeleteReadingItemUrl(first.id), () =>
        problemResponse(503, "Delete unavailable", "SERVICE_UNAVAILABLE"),
      ),
    );
    const user = userEvent.setup();
    renderApp("/");

    await user.click(await screen.findByRole("button", { name: "Delete First item" }));
    await user.click(screen.getByRole("button", { name: "Delete item" }));
    expect(await screen.findByRole("alert")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Keep item" }));

    await user.click(screen.getByRole("button", { name: "Delete Second item" }));
    expect(screen.queryByRole("alert")).toBeNull();
  });
});

describe("identity transitions", () => {
  it("removes reading-list cache data and navigates to login on logout", async () => {
    const queryClient = createTestQueryClient();
    queryClient.setQueryData(readingItemsQueryKey(), { status: 200, data: [readingItem()] });
    let loggedOut = false;
    server.use(
      http.get(serviceHttp.getGetCurrentPrincipalUrl(), () =>
        loggedOut
          ? problemResponse(401, "Authentication required", "AUTHENTICATION_REQUIRED")
          : HttpResponse.json(authenticatedPrincipal),
      ),
      listReadingItemsHandler([readingItem()]),
      http.post(serviceHttp.getLogoutBrowserSessionUrl(), () => {
        loggedOut = true;
        return new HttpResponse(null, { status: 204 });
      }),
    );
    const user = userEvent.setup();
    const { history } = renderApp("/", { queryClient });
    await screen.findByRole("heading", { name: "Reading list" });

    await user.click(screen.getByRole("button", { name: "Sign out" }));

    expect(await screen.findByRole("heading", { name: "Sign in to Reading List" })).toBeTruthy();
    expect(history.location.pathname).toBe("/login");
    expect(queryClient.getQueryData(readingItemsQueryKey())).toBeUndefined();
  });

  it("redirects after a list 401 proves the browser session expired and clears cached items", async () => {
    let principalRequests = 0;
    const queryClient = createTestQueryClient();
    server.use(
      http.get(serviceHttp.getGetCurrentPrincipalUrl(), () => {
        principalRequests += 1;
        return principalRequests === 1
          ? HttpResponse.json(authenticatedPrincipal)
          : problemResponse(401, "Session expired", "AUTHENTICATION_REQUIRED");
      }),
      http.get(serviceHttp.getListReadingItemsUrl(), () =>
        problemResponse(401, "Session expired", "AUTHENTICATION_REQUIRED"),
      ),
    );
    const { history } = renderApp("/", { queryClient });

    expect(await screen.findByRole("heading", { name: "Sign in to Reading List" })).toBeTruthy();
    expect(history.location.pathname).toBe("/login");
    expect(queryClient.getQueryData(readingItemsQueryKey())).toBeUndefined();
  });
});
