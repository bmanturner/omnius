import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { UploadInitiationRequest, UploadPorts } from "@omnius/web-sdk/uploads";

import { UploadPanel } from "../src/components/upload-panel";

describe("UploadPanel", () => {
  it("gives each selected-file action one retry-stable workflow identity", async () => {
    const initiation = vi.fn(async (request: UploadInitiationRequest) => ({
      decision: "started" as const,
      uploadId: "upload-1",
      transfer: {
        mode: "proxied" as const,
        parts: [{
          partNumber: 1,
          offset: 0,
          length: request.byteLength,
          target: {
            url: "/uploads/upload-1/content",
            method: "PUT" as const,
            headers: {},
            body: { kind: "raw" as const },
          },
        }],
      },
    }));
    const ports: UploadPorts = {
      initiate: initiation,
      transfer: async (request) => ({ partNumber: request.part.partNumber, receipt: "http-204" }),
      finalize: async () => ({ state: "available" }),
      getStatus: async () => ({ state: "available" }),
      abandon: async () => {},
    };
    render(
      <UploadPanel
        createIdempotencyKey={() => "action-1"}
        ports={ports}
        workflowKey="account-upload:subject-1"
      />,
    );

    const input = screen.getByLabelText("Choose file");
    const file = new File(
      [new Uint8Array([0x89, 0x50, 0x4e, 0x47])],
      "safe.png",
      { type: "image/png" },
    );
    Object.defineProperty(input, "files", {
      configurable: true,
      value: {
        0: file,
        length: 1,
        item: (index: number) => index === 0 ? file : null,
      },
    });
    fireEvent.change(input);

    await waitFor(() => expect(initiation).toHaveBeenCalledOnce());
    expect(initiation.mock.calls[0]?.[0].identity).toEqual({
      workflowKey: "account-upload:subject-1:action-1",
      idempotencyKey: "action-1",
    });
    await waitFor(() => expect(screen.getByText("Upload is available.")).toBeTruthy());
  });
});
