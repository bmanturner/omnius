import { ServiceProblemError } from "../client/transport.js";
import type { ServiceClient } from "../client/transport.js";
import { getCurrentPrincipal } from "../internal/generated/http/core.js";
import type { CurrentPrincipalPort, CurrentPrincipalResult } from "./types.js";

/** Binds the generated `getCurrentPrincipal` operation to an explicit service client. */
export function createGeneratedCurrentPrincipalPort(
  client: ServiceClient,
): CurrentPrincipalPort {
  return Object.freeze({
    async getCurrentPrincipal({ signal }: { readonly signal?: AbortSignal } = {}): Promise<CurrentPrincipalResult> {
      try {
        return await getCurrentPrincipal(
          client.requestOptions(signal === undefined ? {} : { signal }),
        );
      } catch (error: unknown) {
        if (error instanceof ServiceProblemError && error.status === 401) {
          return Object.freeze({
            status: 401,
            data: Object.freeze({ code: error.code }),
          });
        }
        throw error;
      }
    },
  });
}
