export {
  CONTRACT_AGGREGATE_SHA256,
  CONTRACT_COMPATIBILITY_WINDOW,
  GENERATED_AGAINST_CONTRACT_HASH,
} from "../internal/generated/contract-metadata.js";
export type { ContractCompatibilityWindow } from "../internal/generated/contract-metadata.js";
export * as serviceHttp from "../internal/generated/http/core.js";

export { AUTH_MODES, isAuthMode } from "./auth.js";
export type {
  AuthAdapter,
  AuthMode,
  AuthRequestAuthorization,
  AuthRequestContext,
} from "./auth.js";

export {
  AbortedRequestError,
  ContractMismatchError,
  InvalidResponseError,
  NetworkRequestError,
  RUNTIME_CONTRACT_HASH_HEADER,
  RUNTIME_MAXIMUM_SDK_HEADER,
  RUNTIME_MINIMUM_SDK_HEADER,
  ServiceClientConfigurationError,
  ServiceClientError,
  ServiceProblemError,
  createServiceClient,
  defineServiceClientConfiguration,
  normalizeServiceBaseUrl,
  parseRetryAfter,
} from "./transport.js";
export type {
  ClientHeaders,
  ClientProblemNotification,
  ClientRequestContext,
  ContractMismatchNotification,
  DefinedServiceClientConfiguration,
  ProblemFieldViolation,
  ServiceClient,
  ServiceClientConfiguration,
  ServiceClientErrorKind,
  ServiceRequestOptions,
  ServiceResponse,
} from "./transport.js";

export { normalizePublicBasePath } from "./public-base.js";

export {
  IDEMPOTENT_HTTP_METHODS,
  isIdempotentHttpMethod,
  isValidIdempotencyKey,
  retryDelayMs,
  shouldRetryRequest,
  validateRetryPolicy,
} from "./retry.js";
export type {
  IdempotentHttpMethod,
  RetryClassification,
  RetryDecisionInput,
  RetryPolicy,
} from "./retry.js";

export {
  IDEMPOTENCY_KEY_HEADER,
  createIdempotencyKey,
  createIdempotencySequence,
  parseIdempotencyKey,
} from "./idempotency.js";
export type { IdempotencyKey, IdempotencySequence } from "./idempotency.js";

export {
  parseCursorPagination,
  parseOpaqueCursor,
  scopeQueryKey,
  serializeCursorPagination,
} from "./pagination.js";
export type { CursorPagination, OpaqueCursor, QueryKeyScope } from "./pagination.js";

export {
  ETAG_HEADER,
  IF_MATCH_HEADER,
  OPTIMISTIC_CONCURRENCY_RESOLUTIONS,
  createVersionEntityTag,
  isOptimisticConcurrencyStatus,
  parseStrongEntityTag,
  readStrongEntityTag,
  withIfMatch,
} from "./etag.js";
export type {
  IfMatchValue,
  OptimisticConcurrencyResolution,
  StrongEntityTag,
} from "./etag.js";
