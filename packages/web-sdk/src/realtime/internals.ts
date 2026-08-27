import { normalizePublicBasePath } from "../client/public-base.js";

import type {
  RealtimeClock,
  RealtimeTimers,
} from "./types.js";

export const defaultClock: RealtimeClock = {
  now: () => Date.now(),
};

export const defaultTimers: RealtimeTimers = {
  setTimeout: (callback, delayMs) => globalThis.setTimeout(callback, delayMs),
  clearTimeout: (handle) => globalThis.clearTimeout(handle as number),
};

export function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new RangeError(`${name} must be a positive safe integer`);
  }
  return value;
}

export function nonNegativeFinite(value: number, name: string): number {
  if (!Number.isFinite(value) || value < 0) {
    throw new RangeError(`${name} must be a non-negative finite number`);
  }
  return value;
}

export function abortError(): DOMException {
  return new DOMException("The operation was aborted", "AbortError");
}

export function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) {
    throw signal.reason ?? abortError();
  }
}

export function utf8ByteLength(value: string): number {
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x80) {
      bytes += 1;
    } else if (code < 0x800) {
      bytes += 2;
    } else if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes += 4;
        index += 1;
      } else {
        bytes += 3;
      }
    } else {
      bytes += 3;
    }
  }
  return bytes;
}

export function validateUuidV7(value: string, name: string): void {
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
      value,
    )
  ) {
    throw new TypeError(`${name} must be a canonical UUIDv7`);
  }
}

export function validateTopic(topic: string): void {
  if (!/^[A-Za-z0-9._:/-]{1,128}$/.test(topic)) {
    throw new TypeError("Realtime topic does not satisfy the wire contract");
  }
}

export function validateCursor(cursor: string): void {
  if (cursor.length === 0 || cursor.length > 256 || !/^[!-~]+$/.test(cursor)) {
    throw new TypeError("Realtime cursor does not satisfy the wire contract");
  }
}

export function configuredBaseUrl(baseUrl: string | URL | undefined): URL {
  if (baseUrl === undefined) {
    if (typeof globalThis.location !== "undefined") {
      return new URL(globalThis.location.href);
    }
    throw new TypeError("A baseUrl is required outside a browser environment");
  }

  const value = baseUrl.toString();
  if (value.startsWith("/")) {
    if (typeof globalThis.location === "undefined") {
      throw new TypeError("A root-relative baseUrl requires a browser environment");
    }
    return new URL(normalizePublicBasePath(value), globalThis.location.origin);
  }
  return new URL(value);
}

function resolveDefaultUrl(defaultPath: string, base: URL): URL {
  const directory = new URL(base);
  directory.pathname = `${directory.pathname.replace(/\/+$/u, "")}/`;
  directory.search = "";
  directory.hash = "";
  return new URL(defaultPath.replace(/^\/+/u, ""), directory);
}

export function resolveHttpUrl(
  configured: string | URL | undefined,
  defaultPath: string,
  baseUrl: string | URL | undefined,
): { readonly base: URL; readonly url: URL } {
  const base = configuredBaseUrl(baseUrl);
  const url =
    configured === undefined
      ? resolveDefaultUrl(defaultPath, base)
      : new URL(configured.toString(), base);
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new TypeError("Realtime SSE URLs must use http or https");
  }
  return { base, url };
}

export function resolveWebSocketUrl(
  configured: string | URL | undefined,
  defaultPath: string,
  baseUrl: string | URL | undefined,
): { readonly base: URL; readonly url: URL } {
  const base = configuredBaseUrl(baseUrl);
  const url =
    configured === undefined
      ? resolveDefaultUrl(defaultPath, base)
      : new URL(configured.toString(), base);
  if (url.protocol === "http:") {
    url.protocol = "ws:";
  } else if (url.protocol === "https:") {
    url.protocol = "wss:";
  }
  if (url.protocol !== "ws:" && url.protocol !== "wss:") {
    throw new TypeError("Realtime WebSocket URLs must use ws or wss");
  }
  return { base, url };
}

export function isSameOrigin(base: URL, target: URL): boolean {
  const targetHttpProtocol =
    target.protocol === "ws:"
      ? "http:"
      : target.protocol === "wss:"
        ? "https:"
        : target.protocol;
  const baseHttpProtocol =
    base.protocol === "ws:"
      ? "http:"
      : base.protocol === "wss:"
        ? "https:"
        : base.protocol;
  return (
    targetHttpProtocol === baseHttpProtocol &&
    target.hostname === base.hostname &&
    normalizedPort(targetHttpProtocol, target.port) ===
      normalizedPort(baseHttpProtocol, base.port)
  );
}

function normalizedPort(protocol: string, port: string): string {
  if (port !== "") {
    return port;
  }
  return protocol === "https:" ? "443" : "80";
}
