// @vitest-environment jsdom

import { QueryClient } from "@tanstack/react-query";
import { act, render, screen } from "@testing-library/react";
import { createElement } from "react";
import type { ReactElement } from "react";
import { describe, expect, it } from "vitest";

import type {
  AuthManager,
  AuthSessionListener,
  AuthSessionState,
} from "../src/auth/index.js";
import {
  RequirePermission,
  WebSdkProvider,
  useCurrentPrincipal,
} from "../src/react/index.js";

interface ControlledAuthManager extends AuthManager {
  publish(state: AuthSessionState): void;
  readonly unsubscribeCount: number;
}

function createControlledAuthManager(initial: AuthSessionState): ControlledAuthManager {
  let state = initial;
  let unsubscribeCount = 0;
  const listeners = new Set<AuthSessionListener>();
  return {
    mode: "session",
    requestCredentials: "same-origin",
    authorize() {
      return { headers: {} };
    },
    getSnapshot() {
      return state;
    },
    async getSession() {
      return state;
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => {
        unsubscribeCount += 1;
        listeners.delete(listener);
      };
    },
    publish(next) {
      state = next;
      for (const listener of listeners) {
        listener(next);
      }
    },
    dispose() {},
    get unsubscribeCount() {
      return unsubscribeCount;
    },
  };
}

function authenticatedSession(permissions: readonly string[]): AuthSessionState {
  return {
    status: "authenticated",
    mode: "session",
    principal: { subject: "principal-1", kind: "user", displayName: "Reader" },
    session: {
      authenticatedAt: "2026-08-27T10:00:00Z",
      authenticationMethod: "password",
      assurance: "aal1",
    },
    presentation: { permissions, resourcePermissions: [] },
    scopes: ["openid"],
    tenant: { id: "tenant-1" },
  };
}

function CurrentPrincipalName(): ReactElement {
  const principal = useCurrentPrincipal();
  return createElement("span", null, principal?.displayName ?? "anonymous");
}

function renderGuard(manager: AuthManager) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    createElement(
      WebSdkProvider,
      {
        configuration: { baseUrl: "/api" },
        authManager: manager,
        queryClient,
      },
      createElement(
        RequirePermission,
        { permission: "records.read" },
        createElement("div", null, "protected records"),
      ),
      createElement(CurrentPrincipalName),
    ),
  );
}

describe("React auth integration", () => {
  it("renders an accessible loading state without protected-content flash, then allows", async () => {
    const manager = createControlledAuthManager({
      status: "loading",
      mode: "session",
      reason: "initial",
    });
    const view = renderGuard(manager);

    expect(screen.getByRole("status").textContent).toContain("Checking your session");
    expect(screen.queryByText("protected records")).toBeNull();
    await act(async () => {
      manager.publish(authenticatedSession(["records.read"]));
    });
    expect(screen.getByText("protected records")).toBeTruthy();
    expect(screen.getByText("Reader")).toBeTruthy();

    view.unmount();
    expect(manager.unsubscribeCount).toBeGreaterThan(0);
  });

  it("renders an accessible presentation-only denial", () => {
    const manager = createControlledAuthManager(authenticatedSession([]));
    const view = renderGuard(manager);

    expect(screen.getByRole("alert").textContent).toContain("do not have permission");
    expect(screen.queryByText("protected records")).toBeNull();
    view.unmount();
  });
});
