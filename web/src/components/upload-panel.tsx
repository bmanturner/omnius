import { useEffect, useRef, useState, type ChangeEvent } from "react";

import {
  createUploadCoordinator,
  createUploadWorkflowIdentity,
  type UploadCoordinator,
  type UploadPorts,
  type UploadState,
} from "@omnius/web-sdk/uploads";
import { useUploadCoordinator } from "@omnius/web-sdk/react";

export interface UploadPanelProps {
  readonly ports: UploadPorts;
  /** Stable business identity for this upload field or aggregate. */
  readonly workflowKey: string;
  readonly accept?: string;
  readonly disabled?: boolean;
  readonly onAvailable?: (uploadId: string) => void;
  readonly createIdempotencyKey?: () => string;
}

/** File selection, progress, controlled retry, cancellation, and durable abandonment UI. */
export function UploadPanel({
  ports,
  workflowKey,
  accept,
  disabled = false,
  onAvailable,
  createIdempotencyKey = () => globalThis.crypto.randomUUID(),
}: UploadPanelProps) {
  const [coordinator, setCoordinator] = useState<UploadCoordinator>();
  const current = useRef<UploadCoordinator | undefined>(undefined);

  useEffect(
    () => () => {
      if (current.current !== undefined) void current.current.dispose();
    },
    [],
  );

  const selectFile = (event: ChangeEvent<HTMLInputElement>): void => {
    const file = event.target.files?.item(0);
    if (file === null || file === undefined) return;
    if (current.current !== undefined) void current.current.dispose();
    const next = createUploadCoordinator(
      { data: file, fileName: file.name, ...(file.type.length === 0 ? {} : { mediaType: file.type }) },
      createUploadWorkflowIdentity(workflowKey, createIdempotencyKey()),
      ports,
    );
    current.current = next;
    setCoordinator(next);
    event.target.value = "";
  };

  return (
    <section aria-labelledby="upload-panel-title" className="upload-panel">
      <h2 id="upload-panel-title">Upload a file</h2>
      <label>
        <span>Choose file</span>
        <input accept={accept} disabled={disabled} onChange={selectFile} type="file" />
      </label>
      {coordinator === undefined ? (
        <p>No file selected.</p>
      ) : (
        <ActiveUpload
          coordinator={coordinator}
          {...(onAvailable === undefined ? {} : { onAvailable })}
        />
      )}
    </section>
  );
}

function ActiveUpload({
  coordinator,
  onAvailable,
}: {
  readonly coordinator: UploadCoordinator;
  readonly onAvailable?: (uploadId: string) => void;
}) {
  const state = useUploadCoordinator(coordinator, { disposeOnUnmount: false });
  const announced = useRef<string | undefined>(undefined);

  useEffect(() => {
    if (state.status === "available" && announced.current !== state.uploadId) {
      announced.current = state.uploadId;
      onAvailable?.(state.uploadId);
    }
  }, [onAvailable, state]);

  return (
    <div aria-live="polite" className="upload-lifecycle">
      <p>{statusLabel(state)}</p>
      {state.status === "transferring" ? (
        <progress
          aria-label="Upload progress"
          max={state.progress.totalBytes}
          value={state.progress.bytesTransferred}
        >
          {Math.round(state.progress.fraction * 100)}%
        </progress>
      ) : null}
      <div className="upload-actions">
        {state.status === "cancelled" || (state.status === "failed" && state.rejection.retryable) ? (
          <button onClick={() => void coordinator.resume()} type="button">
            Retry
          </button>
        ) : null}
        {isRunning(state) ? (
          <button onClick={() => coordinator.cancel()} type="button">
            Cancel transfer
          </button>
        ) : null}
        {canAbandon(state) ? (
          <button onClick={() => void coordinator.dispose()} type="button">
            Abandon and clean up
          </button>
        ) : null}
      </div>
    </div>
  );
}

function isRunning(state: UploadState): boolean {
  return state.status === "checksumming"
    || state.status === "initiating"
    || state.status === "transferring"
    || state.status === "finalizing"
    || state.status === "quarantined";
}

function canAbandon(state: UploadState): boolean {
  return state.status !== "idle"
    && state.status !== "available"
    && state.status !== "rejected"
    && state.status !== "abandoned"
    && state.status !== "disposed";
}

function statusLabel(state: UploadState): string {
  switch (state.status) {
    case "idle": return "Waiting to start.";
    case "checksumming": return "Checking file integrity locally.";
    case "initiating": return `Authorizing upload (attempt ${String(state.attempt)}).`;
    case "transferring": return `Uploading ${String(Math.round(state.progress.fraction * 100))}%.`;
    case "finalizing": return "Finalizing upload.";
    case "quarantined": return "Uploaded. Content security checks are running.";
    case "available": return "Upload is available.";
    case "cancelled": return "Transfer cancelled. You can retry or abandon it.";
    case "failed": return state.rejection.message;
    case "rejected": return state.rejection.message;
    case "abandoned": return "Upload abandoned; cleanup is scheduled.";
    case "disposed": return state.abandoned ? "Upload abandoned; cleanup is scheduled." : "Upload closed.";
  }
}
