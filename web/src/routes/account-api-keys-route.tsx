import { serviceHttp } from "@omnius/web-sdk/client";
import { serviceQueries, useServiceClient } from "@omnius/web-sdk/react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import type { FormEvent } from "react";

import { EmptyState, LoadingState, ProblemState } from "../components/request-states";

interface OneTimeSecret {
  readonly apiKey: string;
  readonly metadata: serviceHttp.ApiKeyResponse;
  readonly operation: "created" | "rotated";
  readonly listUpdatedAt: number;
}

export function AccountApiKeysRoute() {
  const client = useServiceClient();
  const queryClient = useQueryClient();
  const [serviceAccountName, setServiceAccountName] = useState("");
  const [selectedAccountId, setSelectedAccountId] = useState<string>();
  const [keyName, setKeyName] = useState("");
  const [scopeInput, setScopeInput] = useState("");
  const [oneTimeSecret, setOneTimeSecret] = useState<OneTimeSecret | null>(null);
  const serviceAccountsQuery = useQuery(
    serviceQueries.getListServiceAccountsQueryOptions(
      { limit: 100 },
      { request: client.requestOptions() },
    ),
  );
  const accounts = serviceAccountsQuery.data?.status === 200
    ? serviceAccountsQuery.data.data.items
    : [];

  useEffect(() => {
    if (selectedAccountId === undefined && accounts[0] !== undefined) {
      setSelectedAccountId(accounts[0].id);
    }
  }, [accounts, selectedAccountId]);

  const keysQuery = useQuery({
    ...serviceQueries.getListServiceAccountApiKeysQueryOptions(
      selectedAccountId ?? "",
      { limit: 100 },
      { request: client.requestOptions() },
    ),
    enabled: selectedAccountId !== undefined,
  });
  const keys = keysQuery.data?.status === 200 ? keysQuery.data.data.items : [];
  useEffect(() => {
    if (
      oneTimeSecret !== null &&
      keysQuery.dataUpdatedAt !== 0 &&
      keysQuery.dataUpdatedAt !== oneTimeSecret.listUpdatedAt
    ) {
      setOneTimeSecret(null);
    }
  }, [keysQuery.dataUpdatedAt, oneTimeSecret]);

  const createAccount = useMutation({
    mutationFn: async () => serviceHttp.createServiceAccount(
      { name: serviceAccountName },
      client.requestOptions(),
    ),
    onSuccess: async (response) => {
      if (response.status === 201) {
        setServiceAccountName("");
        setSelectedAccountId(response.data.id);
      }
      await queryClient.invalidateQueries({ queryKey: serviceQueries.getListServiceAccountsQueryKey({ limit: 100 }) });
    },
  });
  const issueKey = useMutation({
    mutationFn: async (body: serviceHttp.IssueApiKeyRequest) => {
      if (selectedAccountId === undefined) throw new TypeError("Select a service account first.");
      const response = await serviceHttp.issueServiceAccountApiKey(
        selectedAccountId,
        body,
        client.requestOptions(),
      );
      if (response.status !== 201) throw new Error("The API key could not be created.");
      setOneTimeSecret({
        apiKey: response.data.api_key,
        metadata: response.data.metadata,
        operation: "created",
        listUpdatedAt: keysQuery.dataUpdatedAt,
      });
      return response.data.metadata;
    },
    onSuccess: () => {
      setKeyName("");
      setScopeInput("");
    },
  });
  const rotateKey = useMutation({
    mutationFn: async (apiKey: serviceHttp.ApiKeyResponse) => {
      const response = await serviceHttp.rotateApiKey(apiKey.id, {}, client.requestOptions());
      if (response.status !== 201) throw new Error("The API key could not be rotated.");
      setOneTimeSecret({
        apiKey: response.data.api_key,
        metadata: response.data.metadata,
        operation: "rotated",
        listUpdatedAt: keysQuery.dataUpdatedAt,
      });
      return response.data.metadata;
    },
  });
  const revokeKey = useMutation({
    mutationFn: async (apiKeyId: string) => serviceHttp.revokeApiKey(apiKeyId, client.requestOptions()),
    onSuccess: async () => {
      if (selectedAccountId !== undefined) {
        await queryClient.invalidateQueries({
          queryKey: serviceQueries.getListServiceAccountApiKeysQueryKey(selectedAccountId, { limit: 100 }),
        });
      }
    },
  });

  const submitAccount = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    createAccount.mutate();
  };
  const submitKey = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    const scopes = scopeInput.split(",").map((scope) => scope.trim()).filter((scope) => scope.length > 0);
    issueKey.mutate({ name: keyName, ...(scopes.length === 0 ? {} : { scopes }) });
  };
  const finishSecretDisplay = async (): Promise<void> => {
    setOneTimeSecret(null);
    if (selectedAccountId !== undefined) {
      await queryClient.invalidateQueries({
        queryKey: serviceQueries.getListServiceAccountApiKeysQueryKey(selectedAccountId, { limit: 100 }),
      });
    }
  };

  if (serviceAccountsQuery.isPending) return <LoadingState label="Loading service accounts" />;
  if (serviceAccountsQuery.isError) return <ProblemState error={serviceAccountsQuery.error} />;

  return (
    <section className="page-section" aria-labelledby="api-keys-title">
      <header className="page-header">
        <p className="eyebrow">Programmatic access</p>
        <h1 id="api-keys-title">API keys</h1>
        <p className="page-intro">Issue scoped credentials to service accounts. Secrets are shown only once.</p>
      </header>
      {oneTimeSecret === null ? null : (
        <section className="one-time-secret" role="status" aria-labelledby="api-key-secret-title">
          <h2 id="api-key-secret-title">Copy this {oneTimeSecret.operation === "created" ? "new" : "rotated"} key now</h2>
          <p>It cannot be displayed again.</p>
          <code>{oneTimeSecret.apiKey}</code>
          <button className="button-link secondary" type="button" onClick={() => void finishSecretDisplay()}>I saved the key</button>
        </section>
      )}
      <div className="account-management-grid">
        <section className="panel" aria-labelledby="service-accounts-heading">
          <header className="panel-header"><h2 id="service-accounts-heading">Service accounts</h2></header>
          <div className="panel-body">
            <form className="record-form" onSubmit={submitAccount}>
              <label className="field" htmlFor="service-account-name">
                Account name
                <input id="service-account-name" className="input" required value={serviceAccountName} onChange={(event) => setServiceAccountName(event.currentTarget.value)} />
              </label>
              <button className="button-link" type="submit" disabled={createAccount.isPending}>Create service account</button>
            </form>
            {createAccount.isError ? <ProblemState error={createAccount.error} /> : null}
            {accounts.length === 0 ? (
              <EmptyState title="No service accounts" detail="Create one to issue an API key." />
            ) : (
              <label className="field" htmlFor="service-account-select">
                Manage account
                <select
                  id="service-account-select"
                  className="select"
                  value={selectedAccountId}
                  onChange={(event) => {
                    setOneTimeSecret(null);
                    setSelectedAccountId(event.currentTarget.value);
                  }}
                >
                  {accounts.map((account) => <option key={account.id} value={account.id}>{account.name}</option>)}
                </select>
              </label>
            )}
          </div>
        </section>
        <section className="panel" aria-labelledby="issue-key-heading">
          <header className="panel-header"><h2 id="issue-key-heading">Issue a key</h2></header>
          <form className="record-form panel-body" onSubmit={submitKey}>
            <label className="field" htmlFor="api-key-name">
              Key name
              <input id="api-key-name" className="input" required value={keyName} onChange={(event) => setKeyName(event.currentTarget.value)} />
            </label>
            <label className="field" htmlFor="api-key-scopes">
              Scopes <span className="field-optional">Optional, comma-separated</span>
              <input id="api-key-scopes" className="input" value={scopeInput} onChange={(event) => setScopeInput(event.currentTarget.value)} />
            </label>
            <button className="button-link" type="submit" disabled={selectedAccountId === undefined || issueKey.isPending}>Issue API key</button>
            {issueKey.isError ? <ProblemState error={issueKey.error} /> : null}
          </form>
        </section>
      </div>
      {selectedAccountId === undefined || keysQuery.isPending ? null : keysQuery.isError ? (
        <ProblemState error={keysQuery.error} />
      ) : keys.length === 0 ? (
        <EmptyState title="No API keys" detail="Issue the first key for this service account." />
      ) : (
        <div className="panel table-scroll api-key-list">
          <table className="records-table">
            <caption className="visually-hidden">API keys for the selected service account</caption>
            <thead><tr><th scope="col">Key</th><th scope="col">Scopes</th><th scope="col">Last used</th><th scope="col">Actions</th></tr></thead>
            <tbody>{keys.map((key) => (
              <tr key={key.id}>
                <td><span className="record-name">{key.name}</span><br /><code className="record-id">{key.key_prefix}…</code></td>
                <td>{key.scopes.length === 0 ? "No scopes" : key.scopes.join(", ")}</td>
                <td>{key.last_used_at ?? "Never"}</td>
                <td className="table-actions">
                  <button className="text-button" type="button" disabled={rotateKey.isPending} onClick={() => rotateKey.mutate(key)}>Rotate</button>
                  <button className="text-button danger-action" type="button" disabled={revokeKey.isPending} onClick={() => revokeKey.mutate(key.id)}>Revoke</button>
                </td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}
      {rotateKey.isError ? <ProblemState error={rotateKey.error} /> : null}
      {revokeKey.isError ? <ProblemState error={revokeKey.error} /> : null}
    </section>
  );
}
