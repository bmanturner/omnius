import {
  GENERATED_AGAINST_CONTRACT_HASH,
  serviceHttp,
} from "@omnius/web-sdk/client";
import { delay, http, HttpResponse } from "msw";
import type { HttpHandler } from "msw";

/**
 * Deliberately reviewed separately from generated SDK metadata. Contract changes keep mocks
 * disabled until their scenarios and fixtures have been checked against the new contract.
 */
export const CONTRACT_MOCKS_REVIEWED_AGAINST =
  "sha256:9d68638cc2acd35e8918fd1577dea7871c5a137cfcce7835dc060b648ff7b82c" as const;

export function assertContractMockCompatibility(
  generatedContractHash: string = GENERATED_AGAINST_CONTRACT_HASH,
): void {
  if (generatedContractHash !== CONTRACT_MOCKS_REVIEWED_AGAINST) {
    throw new Error(
      `Contract mocks target ${CONTRACT_MOCKS_REVIEWED_AGAINST}, but the SDK targets ${generatedContractHash}. Review the fixtures before enabling handlers.`,
    );
  }
}

export function createReferenceRecordFixture(
  overrides: Partial<serviceHttp.ReferenceRecordResponse> = {},
): serviceHttp.ReferenceRecordResponse {
  assertContractMockCompatibility();
  return {
    id: "018f7777-7777-7777-8777-777777777777",
    name: "Fixture record",
    version: 1,
    created_at: "2026-08-20T12:00:00Z",
    updated_at: "2026-08-20T12:00:00Z",
    ...overrides,
  };
}

export function createReferenceRecordPageFixture(
  overrides: Partial<serviceHttp.ReferenceRecordPageResponse> = {},
): serviceHttp.ReferenceRecordPageResponse {
  assertContractMockCompatibility();
  return {
    next_cursor: "fixture-next-cursor",
    ...overrides,
    items: (overrides.items ?? [createReferenceRecordFixture()]).map((record) => ({ ...record })),
  };
}

export function createProblemDetailsFixture(
  overrides: Partial<serviceHttp.ProblemDetailsSchema> = {},
): serviceHttp.ProblemDetailsSchema {
  assertContractMockCompatibility();
  return {
    type: "urn:omnius:problem:unavailable",
    title: "Service unavailable",
    status: 503,
    code: "SERVICE_UNAVAILABLE",
    detail: "Try again shortly.",
    request_id: "req-fixture-503",
    errors: [],
    ...overrides,
  };
}

type ListReferenceRecordsProblemStatus = 400 | 500 | 503;

export type ListReferenceRecordsMockResponse =
  | Readonly<{
      status: 200;
      body: serviceHttp.ReferenceRecordPageResponse;
    }>
  | Readonly<{
      status: ListReferenceRecordsProblemStatus;
      body: serviceHttp.ProblemDetailsSchema;
    }>;

export interface ListReferenceRecordsHandlerOptions {
  readonly response?: ListReferenceRecordsMockResponse;
  readonly latency?: number | "infinite";
  readonly headers?: HeadersInit;
  readonly inspectRequest?: (request: Request) => void | Promise<void>;
}

export function createListReferenceRecordsHandler(
  options: ListReferenceRecordsHandlerOptions = {},
): HttpHandler {
  assertContractMockCompatibility();
  const response = options.response ?? {
    status: 200,
    body: createReferenceRecordPageFixture(),
  };
  const path = serviceHttp.getListReferenceRecordsUrl();

  return http.get(path, async ({ request }) => {
    await options.inspectRequest?.(request);
    if (options.latency !== undefined) {
      await delay(options.latency);
    }
    const headers = new Headers(options.headers);
    if (response.status !== 200) {
      headers.set("Content-Type", "application/problem+json");
    }
    return HttpResponse.json(response.body, {
      status: response.status,
      headers,
    });
  });
}

export function createContractMockHandlers(): readonly HttpHandler[] {
  assertContractMockCompatibility();
  return Object.freeze([createListReferenceRecordsHandler()]);
}
