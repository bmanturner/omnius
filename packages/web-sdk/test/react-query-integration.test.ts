// @vitest-environment jsdom

import { useQueryClient } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { createElement, useMemo } from "react";
import type { ReactElement } from "react";
import { describe, expect, it, vi } from "vitest";

import { serviceHttp } from "../src/client/index.js";
import {
  WebSdkProvider,
  createServiceQueryClient,
  serviceQueries,
  serviceQueryKeys,
  useServiceClient,
} from "../src/react/index.js";

const createdRecord: serviceHttp.ReferenceRecordResponse = {
  id: "018f8888-8888-7888-8888-888888888888",
  name: "Created by mutation",
  version: 1,
  created_at: "2026-08-27T12:00:00Z",
  updated_at: "2026-08-27T12:00:00Z",
};

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function RecordMutationProbe(): ReactElement {
  const client = useServiceClient();
  const queryClient = useQueryClient();
  const request = useMemo(() => client.requestOptions(), [client]);
  const records = serviceQueries.useListReferenceRecords(undefined, { request });
  const createRecord = serviceQueries.useCreateReferenceRecord({
    request,
    mutation: {
      async onSuccess(response) {
        if (response.status === 201) {
          await queryClient.invalidateQueries({
            queryKey: serviceQueryKeys.listReferenceRecords(),
          });
        }
      },
    },
  });

  if (records.isPending) {
    return createElement("p", { role: "status" }, "Loading records");
  }
  if (records.isError || records.data.status !== 200) {
    return createElement("p", { role: "alert" }, "Could not load records");
  }

  return createElement(
    "section",
    null,
    createElement(
      "ul",
      null,
      records.data.data.items.length === 0
        ? createElement("li", null, "No records")
        : records.data.data.items.map((record) => createElement("li", { key: record.id }, record.name)),
    ),
    createElement(
      "button",
      {
        type: "button",
        disabled: createRecord.isPending,
        onClick: () => createRecord.mutate({ data: { name: createdRecord.name } }),
      },
      createRecord.isPending ? "Creating record" : "Create record",
    ),
  );
}

describe("generated React Query integration", () => {
  it("refreshes visible query data after a successful generated mutation invalidates its key", async () => {
    const records: serviceHttp.ReferenceRecordResponse[] = [];
    let listRequests = 0;
    const fetchImplementation: typeof fetch = vi.fn(async (input, init) => {
      const url = new URL(String(input));
      if (url.pathname !== "/reference-records") {
        throw new Error(`Unexpected request path: ${url.pathname}`);
      }
      if ((init?.method ?? "GET") === "POST") {
        const body = JSON.parse(String(init?.body)) as serviceHttp.CreateReferenceRecordRequest;
        expect(body).toEqual({ name: "Created by mutation" });
        records.push(createdRecord);
        return jsonResponse(createdRecord, 201);
      }
      listRequests += 1;
      return jsonResponse({ items: records, next_cursor: "" }, 200);
    });
    const queryClient = createServiceQueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    const view = render(
      createElement(
        WebSdkProvider,
        {
          configuration: {
            baseUrl: "https://api.example.test",
            fetch: fetchImplementation,
          },
          queryClient,
        },
        createElement(RecordMutationProbe),
      ),
    );

    expect(await screen.findByText("No records")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Create record" }));

    expect(await screen.findByText("Created by mutation")).toBeTruthy();
    expect(listRequests).toBe(2);
    expect(fetchImplementation).toHaveBeenCalledTimes(3);
    view.unmount();
  });
});
