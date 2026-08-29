import { serviceHttp } from "@omnius/web-sdk/client";
import { serviceQueries, useAuthManager, useServiceClient } from "@omnius/web-sdk/react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import type { BrowserSessionAuthManager } from "../auth-manager";
import { EmptyState, LoadingState, ProblemState } from "../components/request-states";

const timestampFormatter = new Intl.DateTimeFormat("en-US", {
  dateStyle: "medium",
  timeStyle: "short",
});

function formatTimestamp(value: string): string {
  const timestamp = new Date(value);
  return Number.isNaN(timestamp.valueOf()) ? value : timestampFormatter.format(timestamp);
}

export function AccountSessionsRoute() {
  const client = useServiceClient();
  const manager = useAuthManager() as BrowserSessionAuthManager;
  const queryClient = useQueryClient();
  const sessionsQuery = useQuery(
    serviceQueries.getListActiveSessionsQueryOptions({ request: client.requestOptions() }),
  );
  const revoke = useMutation({
    mutationFn: async (session: serviceHttp.AccountSessionResponseSchema) => {
      await serviceHttp.revokeSessionDevice(session.device_id, client.requestOptions());
      return session;
    },
    onSuccess: async (session) => {
      await queryClient.invalidateQueries({ queryKey: serviceQueries.getListActiveSessionsQueryKey() });
      if (session.current) await manager.getSession();
    },
  });

  if (sessionsQuery.isPending) return <LoadingState label="Loading browser sessions" />;
  if (sessionsQuery.isError) return <ProblemState error={sessionsQuery.error} />;
  const sessions = sessionsQuery.data.status === 200 ? sessionsQuery.data.data.sessions : [];

  return (
    <section className="page-section" aria-labelledby="sessions-title">
      <header className="page-header">
        <p className="eyebrow">Account security</p>
        <h1 id="sessions-title">Browser sessions</h1>
        <p className="page-intro">Review devices signed in to your account and revoke access you no longer recognize.</p>
      </header>
      {revoke.isError ? <ProblemState error={revoke.error} /> : null}
      {sessions.length === 0 ? (
        <EmptyState title="No active sessions" detail="Sign in on a browser to establish a session." />
      ) : (
        <div className="panel table-scroll">
          <table className="records-table">
            <caption className="visually-hidden">Active browser sessions</caption>
            <thead><tr><th scope="col">Device</th><th scope="col">Last active</th><th scope="col">Expires</th><th scope="col">Action</th></tr></thead>
            <tbody>
              {sessions.map((session) => (
                <tr key={session.device_id}>
                  <td>
                    <span className="record-name">{session.current ? "This device" : "Browser device"}</span><br />
                    <code className="record-id">{session.device_id}</code>
                  </td>
                  <td><time dateTime={session.last_seen_at}>{formatTimestamp(session.last_seen_at)}</time></td>
                  <td><time dateTime={session.absolute_expires_at}>{formatTimestamp(session.absolute_expires_at)}</time></td>
                  <td>
                    <button
                      className="text-button danger-action"
                      type="button"
                      disabled={revoke.isPending}
                      onClick={() => revoke.mutate(session)}
                    >
                      {session.current ? "Sign out this device" : "Revoke session"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
