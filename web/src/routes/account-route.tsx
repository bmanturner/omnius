import { serviceHttp } from "@omnius/web-sdk/client";
import {
  RequirePermission,
  createTenantTransitionCoordinator,
  scopeTenantQueryKey,
  useAuthManager,
  useCapabilityRegistry,
  useCompiledCapability,
  useRuntimeCapability,
  useServiceClient,
  useSession,
  type TenantRealtimePort,
} from "@omnius/web-sdk/react";
import type { UploadPorts } from "@omnius/web-sdk/uploads";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { useEffect, useMemo } from "react";

import type { BrowserSessionAuthManager } from "../auth-manager";
import { LoadingState, ProblemState } from "../components/request-states";
import { TenantSwitcher } from "../components/tenant-switcher";
import { UploadPanel } from "../components/upload-panel";
import { useWebRuntimeComposition } from "../runtime-composition";

interface UploadContribution {
  readonly ports: UploadPorts;
  readonly workflowKey: string;
  readonly accept?: string;
  readonly maxBytes?: number;
}

interface AuthenticatedSessionView {
  readonly principal: { readonly subject: string };
  readonly presentation: { readonly permissions: readonly string[] };
  readonly session: {
    readonly assurance: string;
    readonly authenticationMethod: string;
  };
  readonly tenant: { readonly id: string } | null;
}

function TenantControls({ session }: { readonly session: AuthenticatedSessionView }) {
  const client = useServiceClient();
  const manager = useAuthManager();
  const queryClient = useQueryClient();
  const { realtimeManager } = useWebRuntimeComposition();
  const navigate = useNavigate({ from: "/account" });
  const scope = useMemo(
    () => ({
      tenantId: session.tenant?.id ?? null,
      principalId: session.principal.subject,
      permissionScope: JSON.stringify(session.presentation),
    }),
    [session.presentation, session.principal.subject, session.tenant?.id],
  );
  const tenants = useQuery({
    queryKey: scopeTenantQueryKey(["browser-tenants"], scope),
    queryFn: async ({ signal }) => {
      const response = await serviceHttp.listBrowserTenants(client.requestOptions({ signal }));
      if (response.status !== 200) throw new Error("The workspace list was unavailable.");
      return response.data;
    },
  });
  const coordinator = useMemo(
    () =>
      createTenantTransitionCoordinator({
        queryClient,
        initialScope: scope,
        localState: [],
        realtime: (realtimeManager as TenantRealtimePort | null) ?? undefined,
        route: {
          async replaceTenantRoute(): Promise<void> {
            await navigate({ to: "/account", replace: true });
          },
        },
      }),
    [navigate, queryClient, realtimeManager, scope],
  );
  useEffect(() => () => coordinator.dispose(), [coordinator]);

  if (tenants.isPending) return <LoadingState label="Loading workspaces" />;
  if (tenants.isError) return <ProblemState error={tenants.error} />;
  return (
    <section className="panel panel-body" aria-labelledby="workspace-heading">
      <h2 id="workspace-heading">Workspace</h2>
      <TenantSwitcher
        activateTenant={async (tenant, signal) => {
          const response = await serviceHttp.switchBrowserTenant(
            tenant.tenantId,
            client.requestOptions({ signal }),
          );
          if (response.status !== 200) throw new Error("The workspace switch was rejected.");
          await manager.getSession({ signal });
        }}
        coordinator={coordinator}
        principalId={session.principal.subject}
        tenants={tenants.data}
      />
    </section>
  );
}

function OptionalTenantControls({ session }: { readonly session: AuthenticatedSessionView }) {
  const registry = useCapabilityRegistry();
  const compiled = useCompiledCapability(registry, "web-tenancy");
  const runtime = useRuntimeCapability(registry, "web-tenancy");
  return compiled.compiled && runtime.available ? <TenantControls session={session} /> : null;
}

function OptionalUploadControls() {
  const registry = useCapabilityRegistry();
  const compiled = useCompiledCapability(registry, "web-uploads");
  const runtime = useRuntimeCapability(registry, "web-uploads");
  const { contributions } = useWebRuntimeComposition();
  const upload = contributions.uploads as UploadContribution | undefined;
  if (!compiled.compiled || !runtime.available || upload === undefined) return null;
  return (
    <RequirePermission permission="uploads.create" denied={null}>
      <section className="panel panel-body" aria-labelledby="upload-heading">
        <h2 id="upload-heading">Upload</h2>
        <UploadPanel
          {...(upload.accept === undefined ? {} : { accept: upload.accept })}
          {...(upload.maxBytes === undefined ? {} : { maxBytes: upload.maxBytes })}
          ports={upload.ports}
          workflowKey={upload.workflowKey}
        />
      </section>
    </RequirePermission>
  );
}

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
      <OptionalTenantControls session={session} />
      <OptionalUploadControls />
      <nav className="account-destination-list" aria-label="Account management">
        <Link to="/account/security"><strong>Security</strong><span>Change your password.</span></Link>
        <Link to="/account/sessions"><strong>Browser sessions</strong><span>Review and revoke signed-in devices.</span></Link>
        <Link to="/account/api-keys"><strong>API keys</strong><span>Manage service accounts and scoped credentials.</span></Link>
        <Link to="/account/connected-apps"><strong>Connected applications</strong><span>Review and revoke OAuth access.</span></Link>
      </nav>
    </section>
  );
}
