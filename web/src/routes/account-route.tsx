import { useAuthManager, useSession } from "@omnius/web-sdk/react";
import { useMutation } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";

import type { BrowserSessionAuthManager } from "../auth-manager";
import { LoadingState, ProblemState } from "../components/request-states";

export function AccountRoute() {
  const sessionQuery = useSession();
  const manager = useAuthManager() as BrowserSessionAuthManager;
  const navigate = useNavigate({ from: "/account" });
  const logout = useMutation({
    mutationFn: async () => manager.logout(),
    onSuccess: async () => navigate({ to: "/login", replace: true }),
  });
  const session = sessionQuery.data;

  if (session === undefined || session.status === "loading") {
    return <LoadingState label="Loading your account" />;
  }
  if (session.status !== "authenticated") {
    return <ProblemState error={new Error("Your authenticated session is unavailable.")} />;
  }

  return (
    <section className="page-section" aria-labelledby="account-title">
      <header className="page-header account-header">
        <div>
          <p className="eyebrow">Account</p>
          <h1 id="account-title">Your account</h1>
          <p className="page-intro">Manage sign-in security, browser sessions, API access, and connected applications.</p>
        </div>
        <button
          type="button"
          className="secondary-button"
          disabled={logout.isPending}
          onClick={() => logout.mutate()}
        >
          {logout.isPending ? "Signing out…" : "Sign out"}
        </button>
      </header>
      {logout.isError ? <ProblemState error={logout.error} /> : null}
      <dl className="definition-list account-summary">
        <dt>Subject</dt>
        <dd><code>{session.principal.subject}</code></dd>
        <dt>Authentication</dt>
        <dd>{session.session.authenticationMethod}</dd>
        <dt>Assurance</dt>
        <dd>{session.session.assurance}</dd>
      </dl>
      <nav className="account-destination-list" aria-label="Account management">
        <Link to="/account/security"><strong>Security</strong><span>Change your password.</span></Link>
        <Link to="/account/sessions"><strong>Browser sessions</strong><span>Review and revoke signed-in devices.</span></Link>
        <Link to="/account/api-keys"><strong>API keys</strong><span>Manage service accounts and scoped credentials.</span></Link>
        <Link to="/account/connected-apps"><strong>Connected applications</strong><span>Review and revoke OAuth access.</span></Link>
      </nav>
    </section>
  );
}
