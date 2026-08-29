import { serviceHttp } from "@omnius/web-sdk/client";
import { serviceQueries, useServiceClient } from "@omnius/web-sdk/react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { EmptyState, LoadingState, ProblemState } from "../components/request-states";

const consentFormatter = new Intl.DateTimeFormat("en-US", {
  dateStyle: "medium",
  timeStyle: "short",
});

function formatConsentTime(value: string): string {
  const timestamp = new Date(value);
  return Number.isNaN(timestamp.valueOf()) ? value : consentFormatter.format(timestamp);
}

export function AccountConnectedAppsRoute() {
  const client = useServiceClient();
  const queryClient = useQueryClient();
  const grantsQuery = useQuery(
    serviceQueries.getOauthGrantsListQueryOptions({ request: client.requestOptions() }),
  );
  const revoke = useMutation({
    mutationFn: async (grant: serviceHttp.OAuthConnectedGrantSchema) => {
      await serviceHttp.oauthGrantsRevoke(grant.grant_id, client.requestOptions());
      return grant;
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: serviceQueries.getOauthGrantsListQueryKey() });
      await queryClient.invalidateQueries({ queryKey: ["omnius"] });
    },
  });

  if (grantsQuery.isPending) return <LoadingState label="Loading connected applications" />;
  if (grantsQuery.isError) return <ProblemState error={grantsQuery.error} />;
  const grants = grantsQuery.data.status === 200 ? grantsQuery.data.data : [];

  return (
    <section className="page-section" aria-labelledby="connected-apps-title">
      <header className="page-header">
        <p className="eyebrow">Privacy and access</p>
        <h1 id="connected-apps-title">Connected applications</h1>
        <p className="page-intro">Review applications you authorized and revoke access you no longer want to share.</p>
      </header>
      {revoke.isError ? <ProblemState error={revoke.error} /> : null}
      {grants.length === 0 ? (
        <EmptyState title="No connected applications" detail="Applications you authorize will appear here." />
      ) : (
        <ul className="connected-app-list">
          {grants.map((grant) => (
            <li className="panel panel-body" key={grant.grant_id}>
              <div>
                <h2>{grant.client_name}</h2>
                <p className="resource-label">{grant.resource}</p>
                <ul className="scope-list" aria-label={`Access granted to ${grant.client_name}`}>
                  {grant.scopes.map((scope) => <li key={scope}><code>{scope}</code></li>)}
                </ul>
                <p className="field-help">Authorized <time dateTime={grant.consented_at}>{formatConsentTime(grant.consented_at)}</time></p>
              </div>
              <button
                className="button-link secondary danger-action"
                type="button"
                disabled={revoke.isPending}
                onClick={() => revoke.mutate(grant)}
              >
                Revoke access
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
