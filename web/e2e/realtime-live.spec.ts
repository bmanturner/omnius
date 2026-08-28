import type { Page } from "@playwright/test";

import { authenticateBrowserSession, expect, test } from "./fixtures";

const managedFixturePort = Number.parseInt(process.env.OMNIUS_E2E_PORT ?? "4174", 10);
const viteProxyBaseUrl = `http://127.0.0.1:${managedFixturePort + 1}`;
const firstSubscriptionId = "01890f2a-0000-7000-8000-000000000031";
const resumedSubscriptionId = "01890f2a-0000-7000-8000-000000000032";

async function loginThroughVite(page: Page): Promise<void> {
  await page.goto(`${viteProxyBaseUrl}/account`);
  await page.getByLabel("Email").fill("person@example.test");
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Workspace", level: 1 })).toBeVisible();
}

async function openAndCloseEventSource(page: Page, path: string): Promise<void> {
  await page.evaluate(async (url) => {
    await new Promise<void>((resolve, reject) => {
      const source = new EventSource(url);
      const timeout = globalThis.setTimeout(() => {
        source.close();
        reject(new Error("SSE stream did not open before its deadline"));
      }, 5_000);
      source.onopen = () => {
        globalThis.clearTimeout(timeout);
        source.close();
        resolve();
      };
      source.onerror = () => {
        globalThis.clearTimeout(timeout);
        source.close();
        reject(new Error("SSE stream failed before opening"));
      };
    });
  }, path);
}

test("Vite proxies unbuffered SSE and accepts an explicit resume cursor", async ({ page }) => {
  test.skip(
    process.env.OMNIUS_E2E_BASE_URL !== undefined,
    "The Vite proxy workflow belongs to the managed local fixture.",
  );
  await loginThroughVite(page);

  const initialPath = `/events?subscription_id=${firstSubscriptionId}&topic=reference-records`;
  const initialResponse = page.waitForResponse((response) =>
    new URL(response.url()).pathname === "/events"
      && new URL(response.url()).searchParams.get("subscription_id") === firstSubscriptionId,
  );
  await openAndCloseEventSource(page, initialPath);
  const opened = await initialResponse;
  expect(opened.status()).toBe(200);
  expect(opened.headers()["content-type"]).toContain("text/event-stream");
  expect(opened.headers()["content-encoding"]).toBeUndefined();

  const resumedPath = `/events?subscription_id=${resumedSubscriptionId}&topic=reference-records&cursor=cursor-7`;
  const resumedRequest = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.pathname === "/events" && url.searchParams.get("cursor") === "cursor-7";
  });
  await openAndCloseEventSource(page, resumedPath);
  expect(new URL((await resumedRequest).url()).searchParams.get("cursor")).toBe("cursor-7");
});

test("WebSocket subscriptions receive tenant mutations and resubscribe after reconnect", async ({
  page,
}) => {
  await authenticateBrowserSession(page.request);
  await page.goto("/");

  const evidence = await page.evaluate(async () => {
    type WireMessage = {
      readonly type: string;
      readonly payload?: {
        readonly subscription_id?: string;
        readonly topic?: string;
        readonly cursor?: string | null;
      };
    };
    const websocketUrl = new URL("/realtime/ws", globalThis.location.href);
    websocketUrl.protocol = websocketUrl.protocol === "https:" ? "wss:" : "ws:";
    const withDeadline = async <T>(promise: Promise<T>, label: string): Promise<T> => {
      let timeout: ReturnType<typeof globalThis.setTimeout> | undefined;
      const deadline = new Promise<never>((_, reject) => {
        timeout = globalThis.setTimeout(() => reject(new Error(`${label} timed out`)), 5_000);
      });
      try {
        return await Promise.race([promise, deadline]);
      } finally {
        globalThis.clearTimeout(timeout);
      }
    };
    const uuidV7 = (): string => {
      const bytes = crypto.getRandomValues(new Uint8Array(16));
      let timestamp = Date.now();
      for (let index = 5; index >= 0; index -= 1) {
        bytes[index] = timestamp & 0xff;
        timestamp = Math.floor(timestamp / 256);
      }
      bytes[6] = ((bytes.at(6) ?? 0) & 0x0f) | 0x70;
      bytes[8] = ((bytes.at(8) ?? 0) & 0x3f) | 0x80;
      const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
      return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
    };
    const connectAndSubscribe = async (
      cursor?: string,
    ): Promise<{ socket: WebSocket; nextEvent: Promise<WireMessage> }> => {
      const subscriptionId = uuidV7();
      const commandId = uuidV7();
      const socket = new WebSocket(websocketUrl, "omnius.realtime.v1");
      await withDeadline(
        new Promise<void>((resolve, reject) => {
          socket.onopen = () => resolve();
          socket.onerror = () => reject(new Error("WebSocket failed before opening"));
        }),
        "WebSocket open",
      );
      let acknowledge: ((message: WireMessage) => void) | undefined;
      let rejectAcknowledgement: ((reason: Error) => void) | undefined;
      const acknowledgement = new Promise<WireMessage>((resolve, reject) => {
        acknowledge = resolve;
        rejectAcknowledgement = reject;
      });
      let deliverEvent: ((message: WireMessage) => void) | undefined;
      let rejectEvent: ((reason: Error) => void) | undefined;
      const eventPromise = new Promise<WireMessage>((resolve, reject) => {
        deliverEvent = resolve;
        rejectEvent = reject;
      });
      socket.onmessage = (message) => {
        let wire: WireMessage;
        try {
          wire = JSON.parse(String(message.data)) as WireMessage;
        } catch {
          rejectAcknowledgement?.(
            new Error(`invalid WebSocket frame: ${String(message.data)}`),
          );
          return;
        }
        if (
          wire.type === "subscription.created"
          && wire.payload?.subscription_id === subscriptionId
        ) {
          acknowledge?.(wire);
        }
        if (wire.type === "command.rejected") {
          const error = new Error(`subscription rejected: ${JSON.stringify(wire)}`);
          rejectAcknowledgement?.(error);
          rejectEvent?.(error);
        }
        if (
          wire.type === "reference-record.invalidated.v1"
          && wire.payload?.subscription_id === subscriptionId
        ) {
          deliverEvent?.(wire);
        }
      };
      socket.onerror = () => {
        const error = new Error("WebSocket failed while subscribed");
        rejectAcknowledgement?.(error);
        rejectEvent?.(error);
      };
      socket.onclose = (event) => {
        const error = new Error(`WebSocket closed with ${event.code}: ${event.reason}`);
        rejectAcknowledgement?.(error);
        rejectEvent?.(error);
      };
      socket.send(JSON.stringify({
        v: 1,
        id: commandId,
        type: "subscription.create",
        correlation_id: null,
        payload: {
          subscription_id: subscriptionId,
          topic: "reference-records",
          ...(cursor === undefined ? {} : { cursor }),
        },
      }));
      await withDeadline(acknowledgement, "subscription acknowledgement");
      return { socket, nextEvent: withDeadline(eventPromise, "domain event") };
    };
    const mutate = async (suffix: string): Promise<void> => {
      const response = await fetch("/reference-records", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "idempotency-key": `realtime-live-${suffix}`,
        },
        body: JSON.stringify({ name: `Realtime browser ${suffix}` }),
      });
      if (response.status !== 201) {
        throw new Error(`reference mutation returned ${response.status}`);
      }
    };
    const first = await connectAndSubscribe();
    await mutate("first");
    const firstEvent = await first.nextEvent;
    first.socket.close(1000, "exercise reconnect");
    await withDeadline(
      new Promise<void>((resolve) => first.socket.addEventListener("close", () => resolve(), { once: true })),
      "first WebSocket close",
    );
    await new Promise((resolve) => globalThis.setTimeout(resolve, 250));

    const second = await connectAndSubscribe(firstEvent.payload?.cursor ?? undefined);
    await new Promise((resolve) => globalThis.setTimeout(resolve, 100));
    await mutate("second");
    const secondEvent = await second.nextEvent;
    second.socket.close(1000, "test complete");
    return {
      firstType: firstEvent.type,
      secondType: secondEvent.type,
      secondTopic: secondEvent.payload?.topic,
    };
  });

  expect(evidence).toEqual({
    firstType: "reference-record.invalidated.v1",
    secondType: "reference-record.invalidated.v1",
    secondTopic: "reference-records",
  });
});
