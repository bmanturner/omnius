import { createServer } from "node:http";
import type { AddressInfo } from "node:net";

import {
  CONTRACT_MOCKS_REVIEWED_AGAINST,
  assertContractMockCompatibility,
  createListReferenceRecordsHandler,
  createProblemDetailsFixture,
  createReferenceRecordFixture,
  createReferenceRecordPageFixture,
} from "./contract-mocks";
import { server } from "./setup";

describe("contract-derived MSW fixtures", () => {
  it("builds deterministic valid defaults with isolated explicit overrides", () => {
    const first = createReferenceRecordPageFixture();
    const second = createReferenceRecordPageFixture({
      items: [createReferenceRecordFixture({ name: "Overridden record", version: 7 })],
      next_cursor: "overridden-cursor",
    });

    expect(first).toEqual({
      items: [
        {
          id: "018f7777-7777-7777-8777-777777777777",
          name: "Fixture record",
          version: 1,
          created_at: "2026-08-20T12:00:00Z",
          updated_at: "2026-08-20T12:00:00Z",
        },
      ],
      next_cursor: "fixture-next-cursor",
    });
    expect(second.items[0]?.name).toBe("Overridden record");
    expect(second.items[0]?.version).toBe(7);
    expect(second.next_cursor).toBe("overridden-cursor");
    expect(first.items).not.toBe(second.items);
  });

  it("refuses to enable stale mocks before compatibility review", () => {
    expect(() => assertContractMockCompatibility(`sha256:${"0".repeat(64)}`)).toThrow(
      `Contract mocks target ${CONTRACT_MOCKS_REVIEWED_AGAINST}`,
    );
    expect(() => assertContractMockCompatibility()).not.toThrow();
  });

  it("preserves contract problem responses and permits scenario request inspection", async () => {
    let requestedUrl: URL | undefined;
    const problem = createProblemDetailsFixture({
      status: 400,
      code: "INVALID_CURSOR",
      title: "Invalid cursor",
      detail: "Request a fresh page.",
      request_id: "req-invalid-cursor",
    });
    server.use(
      createListReferenceRecordsHandler({
        response: { status: 400, body: problem },
        inspectRequest(request) {
          requestedUrl = new URL(request.url);
        },
      }),
    );

    const response = await fetch(
      new URL("/reference-records?limit=50&cursor=opaque", window.location.href),
    );

    expect(response.status).toBe(400);
    expect(response.headers.get("content-type")).toContain("application/problem+json");
    await expect(response.json()).resolves.toEqual(problem);
    expect(requestedUrl?.searchParams.get("limit")).toBe("50");
    expect(requestedUrl?.searchParams.get("cursor")).toBe("opaque");
  });

  it("blocks an unhandled request instead of reaching an available upstream", async () => {
    const upstream = createServer((_request, response) => {
      response.writeHead(204).end();
    });
    await new Promise<void>((resolve, reject) => {
      upstream.once("error", reject);
      upstream.listen(0, "127.0.0.1", resolve);
    });
    const address = upstream.address() as AddressInfo;

    try {
      await expect(
        fetch(`http://127.0.0.1:${address.port}/not-in-the-reviewed-contract`),
      ).rejects.toThrow();
    } finally {
      await new Promise<void>((resolve, reject) => {
        upstream.close((error) => {
          if (error === undefined) {
            resolve();
          } else {
            reject(error);
          }
        });
      });
    }
  });
});
