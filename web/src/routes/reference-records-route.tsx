import {
  ServiceProblemError,
  createIdempotencyKey,
  createVersionEntityTag,
  isOptimisticConcurrencyStatus,
  withIfMatch,
  serviceHttp,
} from "@omnius/web-sdk/client";
import {
  mapFormProblem,
  serviceQueryKeys,
  useServiceClient,
} from "@omnius/web-sdk/react";
import type { ServerFormErrorModel } from "@omnius/web-sdk/react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import type { ChangeEvent, FormEvent } from "react";

import { EmptyState, LoadingState, ProblemState } from "../components/request-states";
import { useCoordinatedServiceForm } from "./auth-form";

type ReferenceRecord = serviceHttp.ReferenceRecordResponse;
type ReferenceRecordPage = serviceHttp.ReferenceRecordPageResponse;

interface RecordFormFields {
  readonly name: string;
}

interface EditTarget {
  readonly id: string;
  readonly name: string;
  readonly version: number;
}

interface ConflictState {
  readonly recordId: string;
  readonly attemptedName: string;
  readonly status: 409 | 412 | 428;
  readonly requestId?: string;
}

const dateFormatter = new Intl.DateTimeFormat("en-US", {
  dateStyle: "medium",
  timeStyle: "short",
  timeZone: "UTC",
});

const pageSizeByValue: Readonly<Record<string, 10 | 25 | 50 | 100>> = {
  "10": 10,
  "25": 25,
  "50": 50,
  "100": 100,
};

function formatTimestamp(value: string): string {
  const timestamp = new Date(value);
  return Number.isNaN(timestamp.valueOf()) ? value : dateFormatter.format(timestamp);
}

function recordListPath(parameters: {
  readonly limit: number;
  readonly cursor?: string;
  readonly name?: string;
}): string {
  const search = new URLSearchParams({ limit: String(parameters.limit) });
  if (parameters.cursor !== undefined) {
    search.set("cursor", parameters.cursor);
  }
  if (parameters.name !== undefined) {
    search.set("name", parameters.name);
  }
  return `/reference-records?${search.toString()}`;
}

function optimisticConcurrencyStatus(status: number): ConflictState["status"] | undefined {
  if (!isOptimisticConcurrencyStatus(status)) {
    return undefined;
  }
  switch (status) {
    case 409:
    case 412:
    case 428:
      return status;
    default:
      return undefined;
  }
}

function formProblem(error: ServiceProblemError): ServerFormErrorModel<RecordFormFields> {
  return mapFormProblem<RecordFormFields>(
    {
      status: error.status,
      type: error.type,
      code: error.code,
      title: error.title,
      fieldViolations: error.fieldViolations,
      ...(error.detail === undefined ? {} : { detail: error.detail }),
      ...(error.requestId === undefined ? {} : { requestId: error.requestId }),
    },
    {
      formId: "create-reference-record",
      knownFields: ["name"],
      controlIdByField: { name: "create-reference-record-name" },
    },
  );
}

export function ReferenceRecordsRoute() {
  const search = useSearch({ from: "/records" });
  const navigate = useNavigate({ from: "/records" });
  const client = useServiceClient();
  const queryClient = useQueryClient();
  const [filterInput, setFilterInput] = useState(search.name ?? "");
  const [createName, setCreateName] = useState("");
  const [editTarget, setEditTarget] = useState<EditTarget | null>(null);
  const [editName, setEditName] = useState("");
  const [editError, setEditError] = useState<unknown>(null);
  const [conflict, setConflict] = useState<ConflictState | null>(null);
  const [resolvingConflict, setResolvingConflict] = useState(false);

  useEffect(() => {
    setFilterInput(search.name ?? "");
  }, [search.name]);

  const parameters = useMemo(
    () => ({
      limit: search.limit,
      ...(search.cursor === undefined ? {} : { cursor: search.cursor }),
      ...(search.name === undefined ? {} : { name: search.name }),
    }),
    [search.cursor, search.limit, search.name],
  );
  const listQueryKey = useMemo(
    () => serviceQueryKeys.listReferenceRecords(parameters),
    [parameters],
  );
  const records = useQuery({
    queryKey: listQueryKey,
    queryFn: ({ signal }) =>
      client.request<ReferenceRecordPage>(recordListPath(parameters), { signal }),
  });

  const createForm = useCoordinatedServiceForm<string, unknown, RecordFormFields>(formProblem);
  const createProblem = createForm.problem;

  const updateRecord = useMutation({
    mutationFn: ({ id, name, version }: { readonly id: string; readonly name: string; readonly version: number }) =>
      client.request<ReferenceRecord>(`/reference-records/${encodeURIComponent(id)}`, {
        method: "PUT",
        headers: withIfMatch(
          { "Content-Type": "application/json" },
          createVersionEntityTag(version),
        ),
        body: JSON.stringify({ name }),
      }),
    onSuccess: async () => {
      setEditTarget(null);
      setEditName("");
      setEditError(null);
      setConflict(null);
      await queryClient.invalidateQueries({
        queryKey: serviceQueryKeys.listReferenceRecords(),
      });
    },
    onError: (error, variables) => {
      const status =
        error instanceof ServiceProblemError
          ? optimisticConcurrencyStatus(error.status)
          : undefined;
      if (error instanceof ServiceProblemError && status !== undefined) {
        setConflict({
          recordId: variables.id,
          attemptedName: variables.name,
          status,
          ...(error.requestId === undefined ? {} : { requestId: error.requestId }),
        });
        setEditError(null);
        return;
      }
      setEditError(error);
    },
  });

  function changePageSize(event: ChangeEvent<HTMLSelectElement>) {
    void navigate({
      search: {
        limit: pageSizeByValue[event.currentTarget.value] ?? 25,
        ...(search.name === undefined ? {} : { name: search.name }),
      },
      replace: true,
    });
  }

  function submitFilter(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const name = filterInput.trim();
    void navigate({
      search: {
        limit: search.limit,
        ...(name.length === 0 ? {} : { name }),
      },
      replace: true,
    });
  }

  function submitCreate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void createForm
      .submit(createName, (name, signal) =>
        client.request<ReferenceRecord>("/reference-records", {
          method: "POST",
          signal,
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": createIdempotencyKey(),
          },
          body: JSON.stringify({ name }),
        }),
      )
      .then(async (result) => {
        if (result.status !== "succeeded") return;
        setCreateName("");
        await queryClient.invalidateQueries({
          queryKey: serviceQueryKeys.listReferenceRecords(),
        });
      });
  }

  function beginEdit(record: ReferenceRecord) {
    setEditTarget({ id: record.id, name: record.name, version: record.version });
    setEditName(record.name);
    setEditError(null);
    setConflict(null);
  }

  function submitEdit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (editTarget === null) {
      return;
    }
    setEditError(null);
    setConflict(null);
    updateRecord.mutate({ id: editTarget.id, name: editName, version: editTarget.version });
  }

  async function fetchCurrent(recordId: string): Promise<ReferenceRecord> {
    const response = await client.request<ReferenceRecord>(
      `/reference-records/${encodeURIComponent(recordId)}`,
      { method: "GET", retryPolicy: false },
    );
    return response.data;
  }

  async function refreshAfterConflict() {
    if (conflict === null) {
      return;
    }
    setResolvingConflict(true);
    try {
      const current = await fetchCurrent(conflict.recordId);
      setEditTarget({ id: current.id, name: current.name, version: current.version });
      setEditName(current.name);
      setConflict(null);
      await queryClient.invalidateQueries({
        queryKey: serviceQueryKeys.listReferenceRecords(),
      });
    } catch (error: unknown) {
      setEditError(error);
    } finally {
      setResolvingConflict(false);
    }
  }

  async function mergeAfterConflict() {
    if (conflict === null) {
      return;
    }
    setResolvingConflict(true);
    try {
      const current = await fetchCurrent(conflict.recordId);
      setEditTarget({ id: current.id, name: current.name, version: current.version });
      setConflict(null);
      updateRecord.mutate({
        id: current.id,
        name: conflict.attemptedName,
        version: current.version,
      });
    } catch (error: unknown) {
      setEditError(error);
    } finally {
      setResolvingConflict(false);
    }
  }

  const createNameError = createProblem?.fieldErrors.find((error) => error.path === "name");

  return (
    <>
      <header className="page-header">
        <p className="eyebrow">Data</p>
        <h1>Reference records</h1>
        <p className="page-intro">
          Create and update service records with URL-owned filters and version-safe conflict resolution.
        </p>
      </header>

      <section className="panel record-create-panel" aria-labelledby="create-record-heading">
        <header className="panel-header">
          <h2 id="create-record-heading">Create a record</h2>
        </header>
        <form className="record-form panel-body" onSubmit={submitCreate} noValidate>
          {createProblem === null ? null : (
            <div
              id={createProblem.summary.id}
              className="form-error-summary"
              role={createProblem.summary.role}
              aria-live={createProblem.summary.ariaLive}
              tabIndex={createProblem.summary.tabIndex}
            >
              <h3 id={createProblem.summary.headingId}>{createProblem.summary.title}</h3>
              <ul>
                {createProblem.summary.items.map((item) => (
                  <li key={item.id}>
                    {item.href === undefined ? item.message : <a href={item.href}>{item.message}</a>}
                  </li>
                ))}
              </ul>
              {createProblem.support.requestId === undefined ? null : (
                <p>
                  {createProblem.support.requestIdLabel}: <code>{createProblem.support.requestId}</code>
                </p>
              )}
            </div>
          )}
          {createForm.error === null ? null : <ProblemState error={createForm.error} />}
          <label className="field" htmlFor="create-reference-record-name">
            Name
            <input
              id="create-reference-record-name"
              className="input"
              name="name"
              value={createName}
              required
              aria-invalid={createNameError === undefined ? undefined : true}
              aria-describedby={createNameError?.errorId}
              onChange={(event) => setCreateName(event.currentTarget.value)}
            />
          </label>
          {createNameError === undefined ? null : (
            <p id={createNameError.errorId} className="field-error">
              {createNameError.message}
            </p>
          )}
          <button className="button-link" type="submit" disabled={createForm.pending}>
            {createForm.pending ? "Creating…" : "Create record"}
          </button>
        </form>
      </section>

      <form className="records-toolbar" role="search" onSubmit={submitFilter}>
        <label className="field" htmlFor="record-name-filter">
          Filter by name
          <input
            id="record-name-filter"
            className="input"
            type="search"
            value={filterInput}
            onChange={(event) => setFilterInput(event.currentTarget.value)}
          />
        </label>
        <button className="button-link secondary" type="submit">Apply filter</button>
        {search.name === undefined ? null : (
          <Link className="button-link secondary" to="/records" search={{ limit: search.limit }}>
            Clear filter
          </Link>
        )}
        <label className="field">
          Records per page
          <select className="select" value={search.limit} onChange={changePageSize}>
            <option value={10}>10</option>
            <option value={25}>25</option>
            <option value={50}>50</option>
            <option value={100}>100</option>
          </select>
        </label>
        {search.cursor === undefined ? null : (
          <Link
            className="button-link secondary"
            to="/records"
            search={{
              limit: search.limit,
              ...(search.name === undefined ? {} : { name: search.name }),
            }}
          >
            Return to first page
          </Link>
        )}
      </form>

      {records.isPending ? <LoadingState label="Loading reference records" /> : null}
      {records.isError ? <ProblemState error={records.error} /> : null}
      {records.isSuccess && records.data.status !== 200 ? (
        <ProblemState error={new Error("Unexpected service response status.")} />
      ) : null}
      {records.isSuccess && records.data.status === 200 && records.data.data.items.length === 0 ? (
        <EmptyState />
      ) : null}
      {records.isSuccess && records.data.status === 200 && records.data.data.items.length > 0 ? (
        <section className="panel" aria-labelledby="records-heading">
          <header className="panel-header">
            <h2 id="records-heading">Records</h2>
            <span>{records.data.data.items.length} shown</span>
          </header>
          <div className="table-scroll">
            <table className="records-table">
              <thead>
                <tr>
                  <th scope="col">Name</th>
                  <th scope="col">Version</th>
                  <th scope="col">Updated</th>
                  <th scope="col"><span className="visually-hidden">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {records.data.data.items.map((record) => (
                  <tr key={record.id}>
                    <td>
                      <div className="record-name">{record.name}</div>
                      <div className="record-id">{record.id}</div>
                    </td>
                    <td>{record.version}</td>
                    <td>
                      <time dateTime={record.updated_at}>{formatTimestamp(record.updated_at)} UTC</time>
                    </td>
                    <td>
                      <button className="text-button" type="button" onClick={() => beginEdit(record)}>
                        Edit <span className="visually-hidden">{record.name}</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {editTarget === null ? null : (
            <form className="record-form record-edit-form" onSubmit={submitEdit}>
              <h3>Edit {editTarget.name}</h3>
              <label className="field" htmlFor="edit-reference-record-name">
                Name
                <input
                  id="edit-reference-record-name"
                  className="input"
                  value={editName}
                  required
                  onChange={(event) => setEditName(event.currentTarget.value)}
                />
              </label>
              <div className="form-actions">
                <button className="button-link" type="submit" disabled={updateRecord.isPending}>
                  {updateRecord.isPending ? "Saving…" : "Save changes"}
                </button>
                <button
                  className="button-link secondary"
                  type="button"
                  onClick={() => {
                    setEditTarget(null);
                    setConflict(null);
                    setEditError(null);
                  }}
                >
                  Cancel
                </button>
              </div>
              {conflict === null ? null : (
                <div className="conflict-panel" role="alert">
                  <h4>The record changed before your update was saved</h4>
                  <p>
                    The service returned HTTP {conflict.status}. Load the current record, or keep your name and retry against its latest version.
                  </p>
                  {conflict.requestId === undefined ? null : (
                    <p>Request ID: <code>{conflict.requestId}</code></p>
                  )}
                  <div className="form-actions">
                    <button
                      className="button-link secondary"
                      type="button"
                      disabled={resolvingConflict}
                      onClick={() => void refreshAfterConflict()}
                    >
                      Load current record
                    </button>
                    <button
                      className="button-link"
                      type="button"
                      disabled={resolvingConflict}
                      onClick={() => void mergeAfterConflict()}
                    >
                      Keep my name and retry
                    </button>
                  </div>
                </div>
              )}
              {editError === null ? null : <ProblemState error={editError} />}
            </form>
          )}

          <nav className="pagination" aria-label="Reference record pages">
            <span>Page continues from the URL-owned cursor.</span>
            {records.data.data.next_cursor === null || records.data.data.next_cursor.length === 0 ? (
              <span>End of records</span>
            ) : (
              <Link
                className="button-link"
                to="/records"
                search={{
                  limit: search.limit,
                  cursor: records.data.data.next_cursor,
                  ...(search.name === undefined ? {} : { name: search.name }),
                }}
              >
                Next page
              </Link>
            )}
          </nav>
        </section>
      ) : null}
    </>
  );
}
