import { serviceQueries, useServiceClient } from "@omnius/web-sdk/react";
import { useQueries } from "@tanstack/react-query";
import { useMemo } from "react";

import { LoadingState, ProblemState } from "../components/request-states";

export function StatusRoute() {
  const client = useServiceClient();
  const request = useMemo(() => client.requestOptions(), [client]);
  const queries = useMemo(
    () => [
      serviceQueries.getGetReadinessQueryOptions({ request }),
      serviceQueries.getGetRuntimeMetadataQueryOptions({ request }),
    ] as const,
    [request],
  );
  const [readiness, metadata] = useQueries({ queries });

  if (readiness.isPending || metadata.isPending) {
    return (
      <>
        <header className="page-header">
          <p className="eyebrow">Operations</p>
          <h1>Service overview</h1>
          <p className="page-intro">Live runtime identity and deployment health.</p>
        </header>
        <LoadingState label="Contacting the service" />
      </>
    );
  }

  if (readiness.isError) {
    return <ProblemState error={readiness.error} />;
  }
  if (metadata.isError) {
    return <ProblemState error={metadata.error} />;
  }
  if (readiness.data.status !== 200 || metadata.data.status !== 200) {
    return <ProblemState error={new Error("Unexpected service response status.")} />;
  }

  return (
    <>
      <header className="page-header">
        <p className="eyebrow">Operations</p>
        <h1>Service overview</h1>
        <p className="page-intro">Live runtime identity and deployment health.</p>
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
              <dt>Profile</dt>
              <dd>{metadata.data.data.profile}</dd>
              <dt>API version</dt>
              <dd>{metadata.data.data.api_version}</dd>
            </dl>
          </div>
        </section>
        <section className="panel" aria-labelledby="runtime-heading">
          <header className="panel-header">
            <h2 id="runtime-heading">Runtime</h2>
          </header>
          <div className="panel-body">
            <dl className="definition-list">
              <dt>Application</dt>
              <dd>{metadata.data.data.application_version}</dd>
              <dt>Revision</dt>
              <dd className="record-id">{metadata.data.data.build_revision}</dd>
              <dt>Contract</dt>
              <dd className="record-id">{metadata.data.data.contract_hash}</dd>
              <dt>Capabilities</dt>
              <dd>
                {metadata.data.data.capabilities.length === 0
                  ? "None advertised"
                  : metadata.data.data.capabilities.join(", ")}
              </dd>
            </dl>
          </div>
        </section>
      </div>
    </>
  );
}
