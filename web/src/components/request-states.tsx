import { presentServiceError } from "@omnius/web-sdk/react";

export function LoadingState({ label }: { readonly label: string }) {
  return (
    <section className="state-panel" aria-live="polite" aria-busy="true">
      <h2>{label}</h2>
      <div aria-hidden="true">
        <div className="loading-line" />
        <div className="loading-line" />
      </div>
    </section>
  );
}

export function EmptyState() {
  return (
    <section className="state-panel">
      <h2>No reference records yet</h2>
      <p>
        Records created through the service API will appear here. Change the page size or return
        to the first page if you followed an expired continuation link.
      </p>
    </section>
  );
}

export function ProblemState({ error }: { readonly error: unknown }) {
  const problem = presentServiceError(error);
  return (
    <section className="state-panel" data-tone="error" role="alert">
      <h2>{problem.title}</h2>
      <p>{problem.detail}</p>
      {problem.requestId === undefined ? null : (
        <p>
          Request ID: <code className="request-id">{problem.requestId}</code>
        </p>
      )}
    </section>
  );
}
