import { serviceHttp } from "@omnius/web-sdk/client";
import { useServiceClient } from "@omnius/web-sdk/react";
import { useQuery } from "@tanstack/react-query";
import { Link, useSearch } from "@tanstack/react-router";

import { LoadingState, ProblemState } from "../components/request-states";

function AuthorizeInteraction({ request }: { readonly request: string }) {
  const client = useServiceClient();
  const interactionQuery = useQuery({
    queryKey: ["oauth", "authorization-interaction-display"],
    queryFn: async ({ signal }) => serviceHttp.oauthAuthorizeInteraction(
      { request },
      client.requestOptions({ signal }),
    ),
    staleTime: 0,
    gcTime: 0,
    retry: false,
  });

  if (interactionQuery.isPending) return <LoadingState label="Loading authorization request" />;
  if (interactionQuery.isError) return <ProblemState error={interactionQuery.error} />;
  if (interactionQuery.data.status !== 200) {
    return <ProblemState error={new Error("The authorization request is unavailable.")} />;
  }
  const interaction = interactionQuery.data.data;

  return (
    <section className="page-section consent-page" aria-labelledby="authorize-title">
      <header className="page-header">
        <p className="eyebrow">Authorization request</p>
        <h1 id="authorize-title">Allow {interaction.client_name} to connect?</h1>
        <p className="page-intro">
          <strong>{interaction.client_name}</strong> at {interaction.client_origin} is requesting access to {interaction.resource_name}.
        </p>
      </header>
      <section className="panel consent-details" aria-labelledby="consent-resource-title">
        <header className="panel-header"><h2 id="consent-resource-title">Requested access</h2></header>
        <div className="panel-body">
          <dl className="definition-list">
            <dt>Resource</dt><dd>{interaction.resource_name}<br /><code>{interaction.resource}</code></dd>
            <dt>Why</dt><dd>{interaction.resource_description}</dd>
            <dt>Redirects to</dt><dd>{interaction.redirect_host}</dd>
            <dt>Minimum assurance</dt><dd>{interaction.minimum_assurance}</dd>
          </dl>
          <h2 className="consent-scope-heading">Permissions</h2>
          <ul className="consent-scope-list">
            {interaction.scopes.map((scope) => (
              <li key={scope.name}>
                <div><strong>{scope.name}</strong><p>{scope.description}</p></div>
                <span className={scope.newly_requested ? "scope-status new" : "scope-status"}>
                  {scope.newly_requested ? "New" : "Previously approved"}
                </span>
              </li>
            ))}
          </ul>
        </div>
      </section>
      <p className="consent-notice">Only approve if you recognize this application and expected this request.</p>
      <form className="form-actions" method="post" action="/oauth/authorize/decision">
        <input type="hidden" name="request" value={request} />
        <button className="button-link" type="submit" name="decision" value="approve">Allow access</button>
        <button className="button-link secondary" type="submit" name="decision" value="deny">Deny</button>
      </form>
    </section>
  );
}

export function AuthorizeRoute() {
  const search = useSearch({ from: "/authorize" });
  if (search.request === undefined) {
    return (
      <section className="state-panel auth-panel" data-tone="error" role="alert">
        <h1>Authorization request missing</h1>
        <p>Return to the application that asked you to connect and begin again.</p>
        <Link className="button-link secondary" to="/account/connected-apps">Review connected applications</Link>
      </section>
    );
  }
  return <AuthorizeInteraction key={search.request} request={search.request} />;
}
