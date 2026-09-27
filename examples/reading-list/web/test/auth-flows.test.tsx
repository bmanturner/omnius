import { serviceHttp } from "@omnius/web-sdk/client";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { StrictMode } from "react";

import {
  authenticatedPrincipal,
  listReadingItemsHandler,
  problemResponse,
} from "./mock-api";
import { renderApp } from "./render-app";
import { server } from "./setup";

function installSuccessfulLogin(assertBody?: (body: unknown) => void): {
  authenticatedPrincipalRequests: number;
  loginRequests: number;
} {
  let loggedIn = false;
  const probe = { authenticatedPrincipalRequests: 0, loginRequests: 0 };
  server.use(
    http.get(serviceHttp.getGetCurrentPrincipalUrl(), () => {
      if (loggedIn) probe.authenticatedPrincipalRequests += 1;
      return loggedIn
        ? HttpResponse.json(authenticatedPrincipal)
        : problemResponse(401, "Authentication required", "AUTHENTICATION_REQUIRED");
    }),
    http.post(serviceHttp.getLoginBrowserSessionUrl(), async ({ request }) => {
      assertBody?.(await request.json());
      loggedIn = true;
      probe.loginRequests += 1;
      return new HttpResponse(null, { status: 204 });
    }),
    listReadingItemsHandler(),
  );
  return probe;
}

describe("protected routing and login", () => {
  it("shows session loading before redirecting an anonymous protected route with a local returnTo", async () => {
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => { release = resolve; });
    server.use(
      http.get(serviceHttp.getGetCurrentPrincipalUrl(), async () => {
        await blocked;
        return problemResponse(401, "Authentication required", "AUTHENTICATION_REQUIRED");
      }),
    );
    const { history } = renderApp("/");

    expect(await screen.findByRole("heading", { name: "Checking your session" })).toBeTruthy();
    release();

    expect(await screen.findByRole("heading", { name: "Sign in to Reading List" })).toBeTruthy();
    expect(history.location.search).toBe("?returnTo=%2F");
  });

  it("logs in through the generated operation and restores a validated local returnTo", async () => {
    installSuccessfulLogin((body) => {
      expect(body).toEqual({ identifier: "reader@example.test", password: "correct horse battery" });
    });
    const user = userEvent.setup();
    const { history } = renderApp("/login?returnTo=%2F%3Fview%3Dunfinished");
    await screen.findByRole("heading", { name: "Sign in to Reading List" });

    await user.type(screen.getByLabelText("Email address"), "  reader@example.test  ");
    await user.type(screen.getByLabelText("Password"), "correct horse battery");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByRole("heading", { name: "Reading list" })).toBeTruthy();
    expect(history.location.href).toBe("/?view=unfinished");
  });

  it("rejects an external returnTo after successful login", async () => {
    const probe = installSuccessfulLogin();
    const user = userEvent.setup();
    const { history } = renderApp("/login?returnTo=https%3A%2F%2Fevil.example%2Fsteal");
    await screen.findByRole("heading", { name: "Sign in to Reading List" });

    await user.type(screen.getByLabelText("Email address"), "reader@example.test");
    await user.type(screen.getByLabelText("Password"), "correct horse battery");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    await waitFor(() => {
      expect(probe.loginRequests).toBe(1);
      expect(probe.authenticatedPrincipalRequests).toBeGreaterThan(0);
    });

    await waitFor(() => expect(history.location.href).toBe("/"));
    await screen.findByRole("heading", { name: "Reading list" });
  });
});

describe("account lifecycle", () => {
  it("shows the enumeration-safe accepted registration state", async () => {
    server.use(
      http.post(serviceHttp.getRegisterLocalAccountUrl(), async ({ request }) => {
        expect(await request.json()).toEqual({
          email: "new@example.test",
          password: "a sufficiently long password",
        });
        return HttpResponse.json({ status: "accepted" }, { status: 202 });
      }),
    );
    const user = userEvent.setup();
    renderApp("/register");
    await screen.findByRole("heading", { name: "Create your account" });

    await user.type(screen.getByLabelText("Email address"), "new@example.test");
    await user.type(screen.getByLabelText("Password"), "a sufficiently long password");
    await user.click(screen.getByRole("button", { name: "Create account" }));

    expect(await screen.findByRole("heading", { name: "Check your email" })).toBeTruthy();
    expect(screen.getByText(/if the address can be registered/i)).toBeTruthy();
  });

  it("scrubs a verification fragment before one StrictMode submission and never exposes the token", async () => {
    const secret = "verification-secret-that-must-stay-private";
    const log = vi.spyOn(console, "log");
    const warn = vi.spyOn(console, "warn");
    const error = vi.spyOn(console, "error");
    const info = vi.spyOn(console, "info");
    const debug = vi.spyOn(console, "debug");
    let submissions = 0;
    server.use(
      http.post(serviceHttp.getCompleteEmailVerificationUrl(), async ({ request }) => {
        submissions += 1;
        expect(window.location.hash).toBe("");
        const body = await request.json() as Record<string, unknown>;
        expect(body.token === secret).toBe(true);
        return new HttpResponse(null, { status: 204 });
      }),
    );
    window.history.replaceState(null, "", `/verify-email#token=${secret}`);

    renderApp("/verify-email", { wrapper: StrictMode });

    expect(await screen.findByRole("heading", { name: "Your email is verified" })).toBeTruthy();
    expect(submissions).toBe(1);
    expect(window.location.hash).toBe("");
    expect(document.body.textContent?.includes(secret)).toBe(false);
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
    expect([...log.mock.calls, ...warn.mock.calls, ...error.mock.calls, ...info.mock.calls, ...debug.mock.calls].flat().join(" ").includes(secret)).toBe(false);
  });

  it("shows the same accepted recovery state without revealing account existence", async () => {
    server.use(
      http.post(serviceHttp.getRequestPasswordResetUrl(), async ({ request }) => {
        expect(await request.json()).toEqual({ email: "unknown@example.test" });
        return HttpResponse.json({ status: "accepted" }, { status: 202 });
      }),
    );
    const user = userEvent.setup();
    renderApp("/forgot-password");
    await screen.findByRole("heading", { name: "Reset your password" });

    await user.type(screen.getByLabelText("Email address"), "unknown@example.test");
    await user.click(screen.getByRole("button", { name: "Send reset link" }));

    expect(await screen.findByRole("heading", { name: "Check your email" })).toBeTruthy();
    expect(screen.getByText(/if the account is eligible/i)).toBeTruthy();
  });

  it("scrubs a reset fragment before sending the new password and never persists the token", async () => {
    const secret = "reset-secret-that-must-stay-private";
    const log = vi.spyOn(console, "log");
    const warn = vi.spyOn(console, "warn");
    const error = vi.spyOn(console, "error");
    const info = vi.spyOn(console, "info");
    const debug = vi.spyOn(console, "debug");
    server.use(
      http.post(serviceHttp.getCompletePasswordResetUrl(), async ({ request }) => {
        expect(window.location.hash).toBe("");
        const body = await request.json() as Record<string, unknown>;
        expect(body.token === secret).toBe(true);
        expect(body.new_password).toBe("the replacement password");
        return new HttpResponse(null, { status: 204 });
      }),
    );
    window.history.replaceState(null, "", `/reset-password#token=${secret}`);
    const user = userEvent.setup();
    renderApp("/reset-password");
    await screen.findByRole("heading", { name: "Choose a new password" });

    await user.type(screen.getByLabelText("New password"), "the replacement password");
    await user.click(screen.getByRole("button", { name: "Update password" }));

    expect(await screen.findByRole("heading", { name: "Your password has been reset" })).toBeTruthy();
    expect(window.location.hash).toBe("");
    expect(document.body.textContent?.includes(secret)).toBe(false);
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
    expect([...log.mock.calls, ...warn.mock.calls, ...error.mock.calls, ...info.mock.calls, ...debug.mock.calls].flat().join(" ").includes(secret)).toBe(false);
  });

  it("replaces a consumed failed reset token with an explicit recovery path", async () => {
    const secret = "expired-reset-secret";
    server.use(
      http.post(serviceHttp.getCompletePasswordResetUrl(), () =>
        problemResponse(400, "Reset link expired", "TOKEN_REJECTED"),
      ),
    );
    window.history.replaceState(null, "", `/reset-password#token=${secret}`);
    const user = userEvent.setup();
    renderApp("/reset-password");
    await screen.findByRole("heading", { name: "Choose a new password" });

    await user.type(screen.getByLabelText("New password"), "the replacement password");
    await user.click(screen.getByRole("button", { name: "Update password" }));

    expect(
      await screen.findByRole("heading", { name: "We could not reset your password" }),
    ).toBeTruthy();
    expect(screen.getByRole("link", { name: "Request another link" }).getAttribute("href")).toBe(
      "/forgot-password",
    );
    expect(window.location.hash).toBe("");
    expect(document.body.textContent?.includes(secret)).toBe(false);
  });
});

describe("network mock boundary", () => {
  it("rejects every unhandled request", async () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => undefined);
    await expect(fetch("http://localhost/unhandled-reading-list-request")).rejects.toThrow();
    expect(consoleError).toHaveBeenCalled();
  });
});
