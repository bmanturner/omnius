import { useEffect, useRef, useState } from "react";
import type {
  FieldPath,
  FieldValues,
  UseFormClearErrors,
  UseFormSetError,
} from "react-hook-form";
import type { ZodIssue, ZodType } from "zod";

import type { ProblemFieldViolation } from "../client/index.js";

const DEFAULT_PROBLEM_TITLE = "The request could not be completed";
const DEFAULT_PROBLEM_DETAIL = "Review the form and try again.";
const MAX_PRESENTATION_MESSAGE_LENGTH = 1_000;
const unsafePathSegments: Readonly<Record<string, true>> = Object.freeze({
  ["__proto__"]: true,
  prototype: true,
  constructor: true as const,
});
const unsafeControlCharacters = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/gu;
const invalidPointerEscape = /~(?:[^01]|$)/u;

export interface FormProblemDetails {
  readonly status: number;
  readonly type: string;
  readonly code: string;
  readonly title: string;
  readonly detail?: string;
  readonly fieldViolations: readonly ProblemFieldViolation[];
  readonly requestId?: string;
}

export interface FormSupportMetadata {
  readonly status: number;
  readonly problemType: string;
  readonly problemCode: string;
  readonly requestId?: string;
  readonly requestIdLabel?: "Request ID";
}

export interface ServerFieldError<TFields extends FieldValues> {
  readonly path: FieldPath<TFields>;
  readonly pointer: string;
  readonly code: string;
  readonly message: string;
  readonly controlId: string;
  readonly errorId: string;
}

export interface ServerGlobalError {
  readonly code: string;
  readonly message: string;
  readonly pointer?: string;
}

export interface FormErrorSummaryItem<TFields extends FieldValues> {
  readonly id: string;
  readonly code: string;
  readonly message: string;
  readonly path?: FieldPath<TFields>;
  readonly href?: `#${string}`;
}

export interface FormErrorSummary<TFields extends FieldValues> {
  readonly id: string;
  readonly headingId: string;
  readonly title: string;
  readonly role: "alert";
  readonly ariaLive: "polite";
  readonly tabIndex: -1;
  readonly items: readonly FormErrorSummaryItem<TFields>[];
}

export type FormErrorFocus<TFields extends FieldValues> =
  | {
      readonly target: "summary";
      readonly id: string;
      readonly firstField?: FieldPath<TFields>;
    }
  | {
      readonly target: "field";
      readonly id: string;
      readonly path: FieldPath<TFields>;
    };

export interface ServerFormErrorModel<TFields extends FieldValues> {
  readonly fieldErrors: readonly ServerFieldError<TFields>[];
  /** Always includes the problem-level rejection, even when every violation maps to a field. */
  readonly globalErrors: readonly ServerGlobalError[];
  readonly summary: FormErrorSummary<TFields>;
  readonly focus: FormErrorFocus<TFields>;
  readonly support: FormSupportMetadata;
}

export interface MapFormProblemOptions<TFields extends FieldValues> {
  readonly formId: string;
  readonly knownFields: readonly FieldPath<TFields>[];
  /** RFC 6901 segments to remove before matching React Hook Form paths, for example `["body"]`. */
  readonly pointerPrefix?: readonly string[];
  readonly controlIdByField?: Readonly<Partial<Record<FieldPath<TFields>, string>>>;
  readonly focus?: "summary" | "first-field";
  readonly presentMessage?: (message: string, fallback: string) => string;
}

export interface ReactHookFormErrorSink<TFields extends FieldValues> {
  readonly setError: UseFormSetError<TFields>;
  readonly clearErrors: UseFormClearErrors<TFields>;
}

/**
 * Normalizes service-owned display text without interpreting it as markup. React consumers must
 * render the returned string as text, never through an HTML injection API.
 */
export function toPresentationSafeMessage(message: string, fallback: string): string {
  const normalized = message
    .replace(unsafeControlCharacters, "")
    .replace(/\s+/gu, " ")
    .trim();
  const safeFallback = fallback
    .replace(unsafeControlCharacters, "")
    .replace(/\s+/gu, " ")
    .trim();
  const selected = normalized.length === 0 ? safeFallback : normalized;
  if (selected.length <= MAX_PRESENTATION_MESSAGE_LENGTH) {
    return selected;
  }
  return `${selected.slice(0, MAX_PRESENTATION_MESSAGE_LENGTH - 1)}…`;
}

function decodePointerSegment(segment: string): string | undefined {
  if (segment.length === 0 || invalidPointerEscape.test(segment)) {
    return undefined;
  }
  const decoded = segment.replace(/~1/gu, "/").replace(/~0/gu, "~");
  if (
    unsafePathSegments[decoded] === true ||
    decoded.includes(".") ||
    decoded.includes("[") ||
    decoded.includes("]")
  ) {
    return undefined;
  }
  return decoded;
}

/** Converts a safe RFC 6901 pointer into the dot/index notation used by React Hook Form. */
export function problemPointerToFormPath(
  pointer: string,
  pointerPrefix: readonly string[] = [],
): string | undefined {
  if (pointer.length === 0 || pointer === "/" || !pointer.startsWith("/")) {
    return undefined;
  }
  const decoded: string[] = [];
  for (const segment of pointer.slice(1).split("/")) {
    const value = decodePointerSegment(segment);
    if (value === undefined) {
      return undefined;
    }
    decoded.push(value);
  }
  if (
    pointerPrefix.length > decoded.length ||
    pointerPrefix.some((segment, index) => decoded[index] !== segment)
  ) {
    return undefined;
  }
  const pathSegments = decoded.slice(pointerPrefix.length);
  return pathSegments.length === 0 ? undefined : pathSegments.join(".");
}

function encodedIdSegment(value: string): string {
  let encoded = "";
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    const isAsciiLetterOrNumber =
      (codeUnit >= 48 && codeUnit <= 57) ||
      (codeUnit >= 65 && codeUnit <= 90) ||
      (codeUnit >= 97 && codeUnit <= 122);
    encoded += isAsciiLetterOrNumber
      ? value.charAt(index)
      : `_${codeUnit.toString(16).padStart(4, "0")}_`;
  }
  return encoded.length === 0 ? "_empty_" : encoded;
}

export function formFieldControlId(formId: string, path: string): string {
  return `${encodedIdSegment(formId)}--field--${encodedIdSegment(path)}`;
}

export function formFieldErrorId(formId: string, path: string): string {
  return `${formFieldControlId(formId, path)}--server-error`;
}

/** Maps RFC 9457 field violations without dropping the problem-level or unknown-field errors. */
export function mapFormProblem<TFields extends FieldValues>(
  problem: Readonly<FormProblemDetails>,
  options: Readonly<MapFormProblemOptions<TFields>>,
): ServerFormErrorModel<TFields> {
  const present = options.presentMessage ?? toPresentationSafeMessage;
  const knownFields = new Set<string>(options.knownFields);
  const configuredIds = options.controlIdByField as
    | Readonly<Record<string, string | undefined>>
    | undefined;
  const fieldErrors: ServerFieldError<TFields>[] = [];
  const globalErrors: ServerGlobalError[] = [
    Object.freeze({
      code: problem.code,
      message: present(problem.detail ?? problem.title, DEFAULT_PROBLEM_DETAIL),
    }),
  ];

  for (const violation of problem.fieldViolations) {
    const path = problemPointerToFormPath(violation.pointer, options.pointerPrefix);
    const message = present(violation.message, DEFAULT_PROBLEM_DETAIL);
    if (path === undefined || !knownFields.has(path)) {
      globalErrors.push(
        Object.freeze({ code: violation.code, message, pointer: violation.pointer }),
      );
      continue;
    }
    const typedPath = path as FieldPath<TFields>;
    const controlId = configuredIds?.[path] ?? formFieldControlId(options.formId, path);
    fieldErrors.push(
      Object.freeze({
        path: typedPath,
        pointer: violation.pointer,
        code: violation.code,
        message,
        controlId,
        errorId: `${controlId}--server-error`,
      }),
    );
  }

  const summaryId = `${encodedIdSegment(options.formId)}--error-summary`;
  const globalItems: FormErrorSummaryItem<TFields>[] = globalErrors.map((error, index) =>
    Object.freeze({
      id: `${summaryId}--global-${String(index + 1)}`,
      code: error.code,
      message: error.message,
    }),
  );
  const fieldItems: FormErrorSummaryItem<TFields>[] = fieldErrors.map((error, index) =>
    Object.freeze({
      id: `${summaryId}--field-${String(index + 1)}`,
      code: error.code,
      message: error.message,
      path: error.path,
      href: `#${error.controlId}` as const,
    }),
  );
  const firstField = fieldErrors[0];
  const focus: FormErrorFocus<TFields> =
    options.focus === "first-field" && firstField !== undefined
      ? Object.freeze({ target: "field", id: firstField.controlId, path: firstField.path })
      : Object.freeze({
          target: "summary",
          id: summaryId,
          ...(firstField === undefined ? {} : { firstField: firstField.path }),
        });
  const safeRequestId =
    problem.requestId === undefined
      ? undefined
      : toPresentationSafeMessage(problem.requestId, "");
  const support: FormSupportMetadata = Object.freeze({
    status: problem.status,
    problemType: problem.type,
    problemCode: problem.code,
    ...(safeRequestId === undefined || safeRequestId.length === 0
      ? {}
      : { requestId: safeRequestId, requestIdLabel: "Request ID" as const }),
  });

  return Object.freeze({
    fieldErrors: Object.freeze(fieldErrors),
    globalErrors: Object.freeze(globalErrors),
    summary: Object.freeze({
      id: summaryId,
      headingId: `${summaryId}--heading`,
      title: present(problem.title, DEFAULT_PROBLEM_TITLE),
      role: "alert",
      ariaLive: "polite",
      tabIndex: -1,
      items: Object.freeze([...globalItems, ...fieldItems]),
    }),
    focus,
    support,
  });
}

/** Applies server errors after client hints, so the backend rejection remains authoritative. */
export function applyServerFormErrors<TFields extends FieldValues>(
  model: Readonly<ServerFormErrorModel<TFields>>,
  sink: Readonly<ReactHookFormErrorSink<TFields>>,
): void {
  const appliedPaths = new Set<string>();
  for (const error of model.fieldErrors) {
    if (appliedPaths.has(error.path)) {
      continue;
    }
    appliedPaths.add(error.path);
    sink.setError(error.path, {
      type: `server.${error.code}`,
      message: error.message,
    });
  }
  sink.setError("root.server", {
    type: `server.${model.support.problemCode}`,
    message: toPresentationSafeMessage(
      model.globalErrors.map(({ message }) => message).join(" "),
      DEFAULT_PROBLEM_DETAIL,
    ),
  });
}

/** Clears the field paths and root error created by the previous backend rejection. */
export function clearServerFormErrors<TFields extends FieldValues>(
  previous: Readonly<ServerFormErrorModel<TFields>> | undefined,
  sink: Readonly<ReactHookFormErrorSink<TFields>>,
): void {
  if (previous !== undefined) {
    const clearedPaths = new Set<string>();
    for (const error of previous.fieldErrors) {
      if (!clearedPaths.has(error.path)) {
        clearedPaths.add(error.path);
        sink.clearErrors(error.path);
      }
    }
  }
  sink.clearErrors("root.server");
}

export interface ZodClientHint {
  readonly code: string;
  readonly message: string;
  readonly path?: string;
}

export type ZodClientHintResult<TInput, TOutput> =
  | {
      readonly contractInput: TInput;
      readonly acceptedByClientHint: true;
      readonly transformed: TOutput;
      readonly hints: readonly [];
    }
  | {
      readonly contractInput: TInput;
      readonly acceptedByClientHint: false;
      readonly hints: readonly ZodClientHint[];
    };

function zodIssuePath(issue: Readonly<ZodIssue>): string | undefined {
  const segments: string[] = [];
  for (const segment of issue.path) {
    if (typeof segment !== "string" && typeof segment !== "number") {
      return undefined;
    }
    segments.push(String(segment));
  }
  return segments.length === 0 ? undefined : segments.join(".");
}

/**
 * Runs Zod as a client hint while retaining the original contract input. A false result is never
 * proof that the backend would reject the request; only a backend response is authoritative.
 */
export function inspectZodClientHints<TOutput, TInput>(
  schema: ZodType<TOutput, TInput>,
  input: TInput,
): ZodClientHintResult<TInput, TOutput> {
  const result = schema.safeParse(input);
  if (result.success) {
    return Object.freeze({
      contractInput: input,
      acceptedByClientHint: true,
      transformed: result.data,
      hints: Object.freeze([] as const),
    });
  }
  return Object.freeze({
    contractInput: input,
    acceptedByClientHint: false,
    hints: Object.freeze(
      result.error.issues.map((issue) => {
        const path = zodIssuePath(issue);
        return Object.freeze({
          code: issue.code,
          message: toPresentationSafeMessage(issue.message, "Review this value."),
          ...(path === undefined ? {} : { path }),
        });
      }),
    ),
  });
}

export type FormSubmissionPhase =
  | "idle"
  | "submitting"
  | "succeeded"
  | "rejected"
  | "cancelled"
  | "failed"
  | "disposed";

export interface FormSubmissionState {
  readonly phase: FormSubmissionPhase;
  readonly submissionId: number;
}

export type FormSubmissionResult<TOutput, TServerModel> =
  | { readonly status: "succeeded"; readonly value: TOutput }
  | { readonly status: "rejected"; readonly model: TServerModel }
  | { readonly status: "cancelled" }
  | { readonly status: "busy" }
  | { readonly status: "disposed" }
  | { readonly status: "failed"; readonly error: unknown };

export interface FormSubmissionCoordinatorOptions<TServerProblem, TServerModel> {
  readonly getServerProblem: (error: unknown) => TServerProblem | undefined;
  readonly applyServerProblem: (problem: TServerProblem) => TServerModel;
  readonly clearServerErrors: (previous: TServerModel | undefined) => void;
  readonly onStateChange?: (state: Readonly<FormSubmissionState>) => void;
}

export interface FormSubmissionCoordinator<TInput, TOutput, TServerModel> {
  readonly getState: () => Readonly<FormSubmissionState>;
  readonly submit: (
    input: TInput,
    submitter: (input: TInput, signal: AbortSignal) => Promise<TOutput>,
    signal?: AbortSignal,
  ) => Promise<FormSubmissionResult<TOutput, TServerModel>>;
  readonly cancel: (reason?: unknown) => boolean;
  readonly dispose: () => void;
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

/** Coordinates one in-flight request and owns its cancellation lifetime. */
export function createFormSubmissionCoordinator<TInput, TOutput, TServerProblem, TServerModel>(
  options: Readonly<FormSubmissionCoordinatorOptions<TServerProblem, TServerModel>>,
): FormSubmissionCoordinator<TInput, TOutput, TServerModel> {
  let active: AbortController | undefined;
  let disposed = false;
  let previousServerModel: TServerModel | undefined;
  let nextSubmissionId = 0;
  let state: Readonly<FormSubmissionState> = Object.freeze({ phase: "idle", submissionId: 0 });

  const updateState = (phase: FormSubmissionPhase, submissionId: number): void => {
    state = Object.freeze({ phase, submissionId });
    options.onStateChange?.(state);
  };

  const submit = async (
    input: TInput,
    submitter: (input: TInput, signal: AbortSignal) => Promise<TOutput>,
    externalSignal?: AbortSignal,
  ): Promise<FormSubmissionResult<TOutput, TServerModel>> => {
    if (disposed) {
      return Object.freeze({ status: "disposed" });
    }
    if (active !== undefined) {
      return Object.freeze({ status: "busy" });
    }

    const submissionId = ++nextSubmissionId;
    const controller = new AbortController();
    active = controller;
    const forwardAbort = (): void => controller.abort(externalSignal?.reason);
    if (externalSignal?.aborted === true) {
      forwardAbort();
    } else {
      externalSignal?.addEventListener("abort", forwardAbort, { once: true });
    }

    try {
      if (controller.signal.aborted) {
        updateState("cancelled", submissionId);
        return Object.freeze({ status: "cancelled" });
      }
      options.clearServerErrors(previousServerModel);
      previousServerModel = undefined;
      updateState("submitting", submissionId);
      const value = await submitter(input, controller.signal);
      if (controller.signal.aborted) {
        if (!disposed) {
          updateState("cancelled", submissionId);
        }
        return Object.freeze({ status: "cancelled" });
      }
      updateState("succeeded", submissionId);
      return Object.freeze({ status: "succeeded" as const, value });
    } catch (error: unknown) {
      if (disposed) {
        return Object.freeze({ status: "cancelled" });
      }
      const serverProblem = options.getServerProblem(error);
      if (serverProblem !== undefined) {
        previousServerModel = options.applyServerProblem(serverProblem);
        updateState("rejected", submissionId);
        return Object.freeze({ status: "rejected" as const, model: previousServerModel });
      }
      if (controller.signal.aborted || isAbortError(error)) {
        updateState("cancelled", submissionId);
        return Object.freeze({ status: "cancelled" });
      }
      updateState("failed", submissionId);
      return Object.freeze({ status: "failed" as const, error });
    } finally {
      externalSignal?.removeEventListener("abort", forwardAbort);
      if (active === controller) {
        active = undefined;
      }
    }
  };

  return Object.freeze({
    getState: () => state,
    submit,
    cancel: (reason?: unknown): boolean => {
      if (active === undefined) {
        return false;
      }
      active.abort(reason);
      return true;
    },
    dispose: (): void => {
      if (disposed) {
        return;
      }
      disposed = true;
      active?.abort();
      active = undefined;
      updateState("disposed", nextSubmissionId);
    },
  });
}

export interface UseFormSubmissionCoordinatorResult<TInput, TOutput, TServerModel> {
  readonly state: Readonly<FormSubmissionState>;
  readonly submit: FormSubmissionCoordinator<TInput, TOutput, TServerModel>["submit"];
  readonly cancel: FormSubmissionCoordinator<TInput, TOutput, TServerModel>["cancel"];
}

/** React lifetime adapter for the framework-independent submission coordinator. */
export function useFormSubmissionCoordinator<TInput, TOutput, TServerProblem, TServerModel>(
  options: Readonly<FormSubmissionCoordinatorOptions<TServerProblem, TServerModel>>,
): UseFormSubmissionCoordinatorResult<TInput, TOutput, TServerModel> {
  const optionsRef = useRef(options);
  const mountedRef = useRef(true);
  optionsRef.current = options;
  const [state, setState] = useState<Readonly<FormSubmissionState>>(
    Object.freeze({ phase: "idle", submissionId: 0 }),
  );
  const [coordinator] = useState(() =>
    createFormSubmissionCoordinator<TInput, TOutput, TServerProblem, TServerModel>({
      getServerProblem: (error) => optionsRef.current.getServerProblem(error),
      applyServerProblem: (problem) => optionsRef.current.applyServerProblem(problem),
      clearServerErrors: (previous) => optionsRef.current.clearServerErrors(previous),
      onStateChange: (nextState) => {
        if (mountedRef.current) {
          setState(nextState);
          optionsRef.current.onStateChange?.(nextState);
        }
      },
    }),
  );

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      coordinator.cancel();
    };
  }, [coordinator]);
  return Object.freeze({
    state,
    submit: coordinator.submit,
    cancel: coordinator.cancel,
  });
}
