import { useServiceClient } from "@omnius/web-sdk/react";
import { useQuery } from "@tanstack/react-query";

import { LoadingState, ProblemState } from "../components/request-states";

interface ReadinessResponse {
  readonly status: string;
}

export function StatusRoute() {
  const client = useServiceClient();
  const readiness = useQuery({
    queryKey: ["operations", "readiness"],
    queryFn: ({ signal }) => client.request<ReadinessResponse>("/ready", { signal }),
  });

  if (readiness.isPending) {
    return <LoadingState label="Contacting the service" />;
  }
  if (readiness.isError) {
    return <ProblemState error={readiness.error} />;
  }
  if (readiness.data.status !== 200) {
    return <ProblemState error={new Error("Unexpected service response status.")} />;
  }

  return (
    <>
      <header className="page-header">
        <p className="eyebrow">Operations</p>
        <h1>Service overview</h1>
        <p className="page-intro">Live deployment readiness.</p>
      </header>
      <div className="status-grid">
        <section className="panel" aria-labelledby="health-heading">
          <header className="panel-header">
            <h2 id="health-heading">Health</h2>
            <span className="status-indicator">{readiness.data.data.status}</span>
          </header>
          <div className="panel-body">
            <dl className="definition-list">
              <dt>Readiness</dt>
              <dd>{readiness.data.data.status}</dd>
            </dl>
          </div>
        </section>
      </div>
    </>
  );
}
