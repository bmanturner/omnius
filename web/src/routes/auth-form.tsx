import { ServiceProblemError } from "@omnius/web-sdk/client";
import {
  mapFormProblem,
  useFormSubmissionCoordinator,
} from "@omnius/web-sdk/react";
import type {
  FormSubmissionResult,
  ServerFormErrorModel,
} from "@omnius/web-sdk/react";
import { useEffect, useRef, useState } from "react";

export function mapAuthFormProblem<TFields extends object>(
  error: ServiceProblemError,
  formId: string,
  knownFields: Parameters<typeof mapFormProblem<TFields>>[1]["knownFields"],
  controlIdByField: Parameters<typeof mapFormProblem<TFields>>[1]["controlIdByField"],
): ServerFormErrorModel<TFields> {
  return mapFormProblem<TFields>(
    {
      status: error.status,
      type: error.type,
      code: error.code,
      title: error.title,
      fieldViolations: error.fieldViolations,
      ...(error.detail === undefined ? {} : { detail: error.detail }),
      ...(error.requestId === undefined ? {} : { requestId: error.requestId }),
    },
    {
      formId,
      knownFields,
      ...(controlIdByField === undefined ? {} : { controlIdByField }),
    },
  );
}

export interface CoordinatedServiceForm<TInput, TOutput, TFields extends object> {
  readonly problem: ServerFormErrorModel<TFields> | null;
  readonly error: unknown;
  readonly pending: boolean;
  submit(
    input: TInput,
    submitter: (input: TInput, signal: AbortSignal) => Promise<TOutput>,
  ): Promise<FormSubmissionResult<TOutput, ServerFormErrorModel<TFields>>>;
}

/** Shared abort-safe RFC 9457 submission lifetime for browser-auth forms. */
export function useCoordinatedServiceForm<TInput, TOutput, TFields extends object>(
  mapProblem: (error: ServiceProblemError) => ServerFormErrorModel<TFields>,
): CoordinatedServiceForm<TInput, TOutput, TFields> {
  const [problem, setProblem] = useState<ServerFormErrorModel<TFields> | null>(null);
  const [error, setError] = useState<unknown>(null);
  const submission = useFormSubmissionCoordinator<
    TInput,
    TOutput,
    ServiceProblemError,
    ServerFormErrorModel<TFields>
  >({
    getServerProblem: (candidate) =>
      candidate instanceof ServiceProblemError ? candidate : undefined,
    applyServerProblem: (candidate) => {
      const model = mapProblem(candidate);
      setProblem(model);
      return model;
    },
    clearServerErrors: () => {
      setProblem(null);
      setError(null);
    },
  });
  return Object.freeze({
    problem,
    error,
    pending: submission.state.phase === "submitting",
    async submit(input, submitter) {
      const result = await submission.submit(input, submitter);
      if (result.status === "failed") setError(result.error);
      return result;
    },
  });
}

export function FormProblemSummary<TFields extends object>({
  problem,
}: {
  readonly problem: ServerFormErrorModel<TFields>;
}) {
  return (
    <div
      id={problem.summary.id}
      className="form-error-summary"
      role={problem.summary.role}
      aria-live={problem.summary.ariaLive}
      tabIndex={problem.summary.tabIndex}
    >
      <h3 id={problem.summary.headingId}>{problem.summary.title}</h3>
      <ul>
        {problem.summary.items.map((item) => (
          <li key={item.id}>
            {item.href === undefined ? item.message : <a href={item.href}>{item.message}</a>}
          </li>
        ))}
      </ul>
      {problem.support.requestId === undefined ? null : (
        <p>
          {problem.support.requestIdLabel}: <code>{problem.support.requestId}</code>
        </p>
      )}
    </div>
  );
}

export interface FragmentSecretState {
  readonly ready: boolean;
  readonly secret: string | null;
  clear(): void;
}

export function useFragmentSecret(name: "invitation" | "token"): FragmentSecretState {
  const [secret, setSecret] = useState<string | null>(null);
  const [ready, setReady] = useState(false);
  const consumed = useRef(false);

  useEffect(() => {
    if (consumed.current) return;
    consumed.current = true;
    const fragment = new URLSearchParams(globalThis.location.hash.slice(1));
    const values = fragment.getAll(name);
    setSecret(values.length === 1 && values[0]?.length !== 0 ? values[0] ?? null : null);
    globalThis.history.replaceState(
      globalThis.history.state,
      "",
      `${globalThis.location.pathname}${globalThis.location.search}`,
    );
    setReady(true);
  }, [name]);

  return Object.freeze({ ready, secret, clear: () => setSecret(null) });
}
