import type { ComponentType, ReactNode } from "react";

import type { DefinedServiceClientConfiguration } from "../client/index.js";

export interface WebSdkProviderProps {
  readonly configuration: Readonly<DefinedServiceClientConfiguration>;
  readonly children?: ReactNode;
}

/**
 * React-specific registration boundary. The core never imports this module, and React remains
 * an optional peer for consumers that do not use this entry point.
 */
export interface WebSdkReactAdapter {
  readonly Provider: ComponentType<WebSdkProviderProps>;
  readonly useClientConfiguration: () => Readonly<DefinedServiceClientConfiguration>;
}

/** Captures an immutable adapter registration without importing React at runtime. */
export function defineWebSdkReactAdapter(
  adapter: WebSdkReactAdapter,
): Readonly<WebSdkReactAdapter> {
  return Object.freeze({
    Provider: adapter.Provider,
    useClientConfiguration: adapter.useClientConfiguration,
  });
}
