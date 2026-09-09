import { serviceHttp } from "@omnius/web-sdk/client";
import { http, HttpResponse } from "msw";
import type { HttpHandler } from "msw";

export const SUBJECT_ID = "018f7777-7777-7777-8777-777777777777";
export const ITEM_ID = "018f8888-8888-7888-8888-888888888888";

export const authenticatedPrincipal: serviceHttp.PrincipalResponse = Object.freeze({
  subject_id: SUBJECT_ID,
  kind: "user",
  auth_method: "password",
  authenticated_at: "2026-09-08T10:00:00Z",
  assurance: "aal1",
  scopes: [],
  tenant_id: null,
});

export const authenticatedSession: serviceHttp.BrowserSessionResponseSchema = Object.freeze({
  ...authenticatedPrincipal,
  expires_at: "2026-09-08T18:00:00Z",
  presentation_permissions: [],
  resource_permissions: [],
  tenant: null,
});

export function readingItem(
  overrides: Partial<serviceHttp.ReadingItem> = {},
): serviceHttp.ReadingItem {
  return {
    id: ITEM_ID,
    title: "A useful article",
    url: "https://example.test/article",
    finished: false,
    version: 3,
    created_at: "2026-09-08T10:00:00Z",
    updated_at: "2026-09-08T10:00:00Z",
    ...overrides,
  };
}

export function problem(
  status: number,
  title: string,
  code = "SERVICE_ERROR",
): serviceHttp.ProblemDetailsSchema {
  return {
    type: `urn:omnius:problem:${code.toLowerCase()}`,
    title,
    status,
    code,
    detail: title,
    request_id: `req-${status}`,
    errors: [],
  };
}

export function problemResponse(status: number, title: string, code?: string) {
  return HttpResponse.json(problem(status, title, code), {
    status,
    headers: { "Content-Type": "application/problem+json" },
  });
}

export function anonymousPrincipalHandler(): HttpHandler {
  return http.get(serviceHttp.getGetCurrentPrincipalUrl(), () =>
    problemResponse(401, "Authentication required", "AUTHENTICATION_REQUIRED"),
  );
}

export function authenticatedPrincipalHandler(): HttpHandler {
  return http.get(serviceHttp.getGetCurrentPrincipalUrl(), () =>
    HttpResponse.json(authenticatedPrincipal),
  );
}

export function listReadingItemsHandler(
  items: readonly serviceHttp.ReadingItem[] = [],
): HttpHandler {
  return http.get(serviceHttp.getListReadingItemsUrl(), () => HttpResponse.json(items));
}

export function defaultHandlers(): readonly HttpHandler[] {
  return [anonymousPrincipalHandler()];
}
