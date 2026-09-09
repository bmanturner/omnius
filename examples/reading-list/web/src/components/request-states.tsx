import { presentServiceError } from "@omnius/web-sdk/react";

export function LoadingState({ label }: { readonly label: string }) {
  return (
    <section className="state-panel" role="status" aria-live="polite" aria-busy="true">
      <h2>{label}</h2>
      <div aria-hidden="true">
        <div className="loading-line" />
        <div className="loading-line" />
      </div>
    </section>
  );
}

export function EmptyState({
  title = "Nothing here yet",
  detail = "Add your first item to get started.",
}: {
  readonly title?: string;
  readonly detail?: string;
}) {
  return (
    <section className="state-panel">
      <h2>{title}</h2>
      <p>{detail}</p>
    </section>
  );
}

export function ProblemState({ error }: { readonly error: unknown }) {
  const problem = presentServiceError(error);
  return (
    <section className="state-panel" data-tone="error" role="alert" aria-live="assertive">
      <h2>{problem.title}</h2>
      <p>{problem.detail}</p>
      {problem.requestId === undefined ? null : (
        <p>Request ID: <code>{problem.requestId}</code></p>
      )}
    </section>
  );
}
