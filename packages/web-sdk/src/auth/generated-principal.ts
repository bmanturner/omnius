import { ServiceProblemError } from "../client/transport.js";
import type {
  CurrentPrincipalPayload,
  CurrentPrincipalPort,
  CurrentPrincipalResult,
  GetSessionOptions,
} from "./types.js";

export type CurrentPrincipalOperation = (
  options?: GetSessionOptions,
) => Promise<unknown>;

function record(value: unknown, name: string): Readonly<Record<string, unknown>> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${name} must be an object.`);
  }
  return value as Readonly<Record<string, unknown>>;
}

function string(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
    throw new TypeError(`${name} must be a non-empty trimmed string.`);
  }
  return value;
}

function optionalString(value: unknown, name: string): string | undefined {
  return value === undefined ? undefined : string(value, name);
}

function strings(value: unknown, name: string): readonly string[] {
  if (!Array.isArray(value)) {
    throw new TypeError(`${name} must be an array.`);
  }
  return Object.freeze(value.map((item) => string(item, `${name} entry`)));
}

function permissionContext(
  value: unknown,
): Readonly<Record<string, string | number | boolean | null>> {
  const source = record(value, "Resource permission context");
  const normalized: Record<string, string | number | boolean | null> = {};
  for (const [key, item] of Object.entries(source)) {
    if (
      item !== null &&
      typeof item !== "string" &&
      typeof item !== "number" &&
      typeof item !== "boolean"
    ) {
      throw new TypeError("Resource permission context values must be scalar.");
    }
    normalized[key] = item;
  }
  return Object.freeze(normalized);
}

function principalPayload(value: unknown): CurrentPrincipalPayload {
  const source = record(value, "Current-principal response data");
  const tenantValue = source.tenant;
  const tenant =
    tenantValue === undefined || tenantValue === null
      ? tenantValue
      : (() => {
          const value = record(tenantValue, "Current-principal tenant");
          const displayName = optionalString(value.display_name, "Tenant display name");
          return Object.freeze({
            id: string(value.id, "Tenant ID"),
            ...(displayName === undefined ? {} : { display_name: displayName }),
          });
        })();
  const resourcePermissions =
    source.resource_permissions === undefined
      ? undefined
      : (() => {
          if (!Array.isArray(source.resource_permissions)) {
            throw new TypeError("Resource permissions must be an array.");
          }
          return Object.freeze(
            source.resource_permissions.map((item) => {
              const grant = record(item, "Resource permission");
              return Object.freeze({
                permission: string(grant.permission, "Resource permission name"),
                context: permissionContext(grant.context),
              });
            }),
          );
        })();
  const tenantId =
    source.tenant_id === null
      ? null
      : optionalString(source.tenant_id, "Tenant ID");
  const displayName = optionalString(source.display_name, "Principal display name");
  const expiresAt = optionalString(source.expires_at, "Session expiry time");
  const presentationPermissions =
    source.presentation_permissions === undefined
      ? undefined
      : strings(source.presentation_permissions, "Presentation permissions");

  return Object.freeze({
    subject_id: string(source.subject_id, "Principal subject"),
    kind: string(source.kind, "Principal kind"),
    authenticated_at: string(source.authenticated_at, "Session authentication time"),
    auth_method: string(source.auth_method, "Authentication method"),
    assurance: string(source.assurance, "Authentication assurance"),
    scopes: strings(source.scopes, "Principal scopes"),
    ...(tenantId === undefined ? {} : { tenant_id: tenantId }),
    ...(displayName === undefined ? {} : { display_name: displayName }),
    ...(expiresAt === undefined ? {} : { expires_at: expiresAt }),
    ...(presentationPermissions === undefined
      ? {}
      : { presentation_permissions: presentationPermissions }),
    ...(resourcePermissions === undefined
      ? {}
      : { resource_permissions: resourcePermissions }),
    ...(tenant === undefined ? {} : { tenant }),
  });
}

/** Adapts an application-injected current-principal operation to the auth session boundary. */
export function createGeneratedCurrentPrincipalPort(
  operation: CurrentPrincipalOperation,
): CurrentPrincipalPort {
  return Object.freeze({
    async getCurrentPrincipal(options: GetSessionOptions = {}): Promise<CurrentPrincipalResult> {
      try {
        const response = record(
          await operation(options),
          "Current-principal operation result",
        );
        if (
          typeof response.status !== "number" ||
          !Number.isInteger(response.status) ||
          response.status < 100 ||
          response.status > 599
        ) {
          throw new TypeError(
            "Current-principal operation status must be an HTTP status code.",
          );
        }
        if (response.status === 200) {
          return Object.freeze({
            status: 200,
            data: principalPayload(response.data),
          });
        }
        if (response.status === 401) {
          const data = record(response.data, "Current-principal 401 response data");
          return Object.freeze({
            status: 401,
            data: Object.freeze({
              code: string(data.code, "Current-principal problem code"),
            }),
          });
        }
        return Object.freeze({ status: response.status, data: response.data });
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
