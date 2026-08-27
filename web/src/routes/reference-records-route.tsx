import { serviceQueries, useServiceClient } from "@omnius/web-sdk/react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { useMemo } from "react";
import type { ChangeEvent } from "react";

import { EmptyState, LoadingState, ProblemState } from "../components/request-states";

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

export function ReferenceRecordsRoute() {
  const search = useSearch({ from: "/records" });
  const navigate = useNavigate({ from: "/records" });
  const client = useServiceClient();
  const request = useMemo(() => client.requestOptions(), [client]);
  const parameters = useMemo(
    () => ({
      limit: search.limit,
      ...(search.cursor === undefined ? {} : { cursor: search.cursor }),
    }),
    [search.cursor, search.limit],
  );
  const queryOptions = useMemo(
    () => serviceQueries.getListReferenceRecordsQueryOptions(parameters, { request }),
    [parameters, request],
  );
  const records = useQuery(queryOptions);

  function changePageSize(event: ChangeEvent<HTMLSelectElement>) {
    void navigate({
      search: { limit: pageSizeByValue[event.currentTarget.value] ?? 25 },
      replace: true,
    });
  }

  return (
    <>
      <header className="page-header">
        <p className="eyebrow">Data</p>
        <h1>Reference records</h1>
        <p className="page-intro">
          Read-only service records, paged with authenticated continuation cursors.
        </p>
      </header>
      <div className="records-toolbar">
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
          <Link className="button-link secondary" to="/records" search={{ limit: search.limit }}>
            Return to first page
          </Link>
        )}
      </div>
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
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <nav className="pagination" aria-label="Reference record pages">
            <span>Page continues from the URL-owned cursor.</span>
            {records.data.data.next_cursor === null ||
            records.data.data.next_cursor.length === 0 ? (
              <span>End of records</span>
            ) : (
              <Link
                className="button-link"
                to="/records"
                search={{ limit: search.limit, cursor: records.data.data.next_cursor }}
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
