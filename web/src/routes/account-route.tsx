import { createWebSocketTransport } from "@omnius/web-sdk/realtime";
import {
  RealtimeProvider,
  createTenantTransitionCoordinator,
  useRealtime,
  useServiceClient,
} from "@omnius/web-sdk/react";
import { createHttpUploadPorts } from "@omnius/web-sdk/uploads";
import { useQueryClient } from "@tanstack/react-query";
import {
  useCallback,
  useEffect,
  lazy,
  Suspense,
  useMemo,
  useState,
  useSyncExternalStore,
  type FormEvent,
} from "react";

import { TenantSwitcher, type TenantSwitchOption } from "../components/tenant-switcher";

// This intentional lazy boundary keeps the upload coordinator outside the account route budget.
const UploadPanel = lazy(async () => {
  const module = await import("../components/upload-panel");
  return { default: module.UploadPanel };
});

interface BrowserSession {
  readonly subjectId: string;
  readonly tenantId?: string;
}

interface AccountData {
  readonly session: BrowserSession;
  readonly tenants: readonly TenantSwitchOption[];
}

export function AccountRoute() {
  const client = useServiceClient();
  const realtimeConfiguration = useMemo(() => {
    const idFactory = (): string => globalThis.crypto.randomUUID();
    return Object.freeze({
      idFactory,
      transport: createWebSocketTransport({
        baseUrl: client.configuration.baseUrl,
        idFactory,
      }),
    });
  }, [client.configuration.baseUrl]);
  return (
    <RealtimeProvider autoConnect={false} configuration={realtimeConfiguration}>
      <AccountWorkspace />
    </RealtimeProvider>
  );
}

function AccountWorkspace() {
  const client = useServiceClient();
  const realtime = useRealtime();
  const [account, setAccount] = useState<AccountData>();
  const [loading, setLoading] = useState(true);
  const [loginError, setLoginError] = useState<string>();

  const loadAccount = useCallback(async (): Promise<void> => {
    setLoading(true);
    try {
      const sessionResponse = await client.request<unknown>("/auth/session", {
        retryPolicy: false,
      });
      const session = readSession(sessionResponse.data);
      const tenantsResponse = await client.request<unknown>("/tenants", {
        retryPolicy: false,
      });
      const tenants = readTenants(tenantsResponse.data);
      const selectedTenant =
        tenants.find((tenant) => tenant.tenantId === session.tenantId) ?? tenants[0];
      if (selectedTenant !== undefined && selectedTenant.tenantId !== session.tenantId) {
        await client.request(
          `/tenants/${encodeURIComponent(selectedTenant.tenantId)}/switch`,
          { method: "POST", retryPolicy: false },
        );
      }
      const boundSession =
        selectedTenant === undefined
          ? session
          : { ...session, tenantId: selectedTenant.tenantId };
      await realtime.resetForIdentityTransition();
      if (selectedTenant !== undefined) realtime.connect();
      setAccount({ session: boundSession, tenants });
    } catch {
      setAccount(undefined);
    } finally {
      setLoading(false);
    }
  }, [client, realtime]);

  useEffect(() => {
    void loadAccount();
  }, [loadAccount]);

  const login = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    setLoginError(undefined);
    const form = new FormData(event.currentTarget);
    try {
      await client.request("/auth/login", {
        method: "POST",
        retryPolicy: false,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          identifier: String(form.get("identifier") ?? ""),
          password: String(form.get("password") ?? ""),
        }),
      });
      await loadAccount();
    } catch {
      setLoginError("Sign-in failed. Check your credentials and try again.");
    }
  };

  const logout = async (): Promise<void> => {
    await client.request("/auth/logout", { method: "POST", retryPolicy: false });
    await realtime.resetForIdentityTransition();
    setAccount(undefined);
  };

  if (loading) {
    return <p role="status">Loading your account…</p>;
  }
  if (account === undefined) {
    return (
      <section className="page-section auth-panel" aria-labelledby="sign-in-title">
        <header className="page-header">
          <p className="eyebrow">Account</p>
          <h1 id="sign-in-title">Sign in</h1>
          <p>Use your organization credentials. The browser stores only an opaque session cookie.</p>
        </header>
        <form className="record-form" onSubmit={(event) => void login(event)}>
          <label className="field">
            <span>Email</span>
            <input className="input" autoComplete="username" name="identifier" required type="email" />
          </label>
          <label className="field">
            <span>Password</span>
            <input className="input" autoComplete="current-password" minLength={12} name="password" required type="password" />
          </label>
          <button className="button-link" type="submit">Sign in</button>
          {loginError === undefined ? null : <p role="alert">{loginError}</p>}
        </form>
      </section>
    );
  }
  return <AuthenticatedAccount account={account} onLogout={logout} />;
}

function AuthenticatedAccount({
  account,
  onLogout,
}: {
  readonly account: AccountData;
  readonly onLogout: () => Promise<void>;
}) {
  const client = useServiceClient();
  const queryClient = useQueryClient();
  const realtime = useRealtime();
  const initialTenant = account.tenants.find((tenant) => tenant.tenantId === account.session.tenantId)
    ?? account.tenants[0];
  const coordinator = useMemo(
    () => createTenantTransitionCoordinator({
      queryClient,
      initialScope: {
        principalId: account.session.subjectId,
        tenantId: initialTenant?.tenantId ?? null,
        ...(initialTenant === undefined
          ? {}
          : { permissionScope: initialTenant.permissionScope }),
      },
      localState: [],
      realtime: {
        async reestablishForTenant(context) {
          const tenantId = context.next.tenantId;
          if (tenantId === null) return;
          await client.request(`/tenants/${encodeURIComponent(tenantId)}/switch`, {
            method: "POST",
            retryPolicy: false,
            ...(context.signal === undefined ? {} : { signal: context.signal }),
          });
          await realtime.reestablishForTenant(context);
        },
      },
      route: {
        replaceTenantRoute(context) {
          const tenantId = context.next.tenantId;
          if (tenantId === null) return;
          const location = new URL(globalThis.location.href);
          location.searchParams.set("tenant", tenantId);
          globalThis.history.replaceState(globalThis.history.state, "", location);
        },
      },
    }),
    [account.session.subjectId, client, initialTenant?.permissionScope, initialTenant?.tenantId, queryClient, realtime],
  );
  const subscribe = useCallback(
    (listener: () => void) => coordinator.subscribe(() => listener()),
    [coordinator],
  );
  const snapshot = useSyncExternalStore(
    subscribe,
    coordinator.getSnapshot,
    coordinator.getSnapshot,
  );
  const tenantId = snapshot.status === "ready" ? snapshot.scope.tenantId : snapshot.next.tenantId;
  const uploadPorts = useMemo(
    () => tenantId === null ? undefined : createHttpUploadPorts({ client, tenantId }),
    [client, tenantId],
  );

  return (
    <section className="page-section" aria-labelledby="account-title">
      <header className="page-header account-header">
        <div>
          <p className="eyebrow">Account</p>
          <h1 id="account-title">Workspace</h1>
          <p>Signed in as <code>{account.session.subjectId}</code>.</p>
        </div>
        <button type="button" className="secondary-button" onClick={() => void onLogout()}>Sign out</button>
      </header>
      <TenantSwitcher
        coordinator={coordinator}
        principalId={account.session.subjectId}
        tenants={account.tenants}
      />
      {uploadPorts === undefined ? (
        <p role="status">Join an active workspace to upload files.</p>
      ) : (
        <Suspense fallback={<p role="status">Loading upload controls…</p>}>
          <UploadPanel
            key={tenantId}
            ports={uploadPorts}
            workflowKey={`account-upload:${account.session.subjectId}`}
          />
        </Suspense>
      )}
    </section>
  );
}

function readSession(value: unknown): BrowserSession {
  const record = readRecord(value);
  if (typeof record.subject_id !== "string") throw new TypeError("Invalid browser session response");
  return {
    subjectId: record.subject_id,
    ...(typeof record.tenant_id === "string" ? { tenantId: record.tenant_id } : {}),
  };
}

function readTenants(value: unknown): readonly TenantSwitchOption[] {
  if (!Array.isArray(value)) throw new TypeError("Invalid tenant list response");
  return Object.freeze(value.map((entry) => {
    const record = readRecord(entry);
    if (typeof record.tenantId !== "string" || typeof record.name !== "string" || typeof record.permissionScope !== "string") {
      throw new TypeError("Invalid tenant response");
    }
    return Object.freeze({
      tenantId: record.tenantId,
      name: record.name,
      permissionScope: record.permissionScope,
    });
  }));
}

function readRecord(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Expected an object response");
  }
  return value as Record<string, unknown>;
}
