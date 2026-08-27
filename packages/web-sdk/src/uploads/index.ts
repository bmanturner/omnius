export interface UploadSource {
  readonly data: Blob;
  readonly fileName: string;
  readonly mediaType?: string;
}

export interface UploadProgress {
  readonly bytesTransferred: number;
  readonly totalBytes: number;
  readonly fraction: number;
}

export type UploadState =
  | { readonly status: "pending" }
  | { readonly status: "uploading"; readonly progress: UploadProgress }
  | { readonly status: "processing"; readonly uploadId: string }
  | { readonly status: "complete"; readonly uploadId: string }
  | { readonly status: "failed"; readonly reason: string; readonly retryable: boolean };

export interface UploadTask {
  readonly state: UploadState;
  cancel(reason?: string): void;
}

/** Framework-neutral lifecycle boundary implemented by the upload adapter in T141. */
export interface UploadClient {
  start(source: UploadSource, options?: { readonly signal?: AbortSignal }): UploadTask;
}

/** Creates validated progress and defines an empty upload as already complete. */
export function calculateUploadProgress(
  bytesTransferred: number,
  totalBytes: number,
): UploadProgress {
  if (
    !Number.isSafeInteger(bytesTransferred) ||
    !Number.isSafeInteger(totalBytes) ||
    bytesTransferred < 0 ||
    totalBytes < 0 ||
    bytesTransferred > totalBytes
  ) {
    throw new RangeError(
      "Upload byte counts must be non-negative safe integers and transferred bytes cannot exceed total bytes.",
    );
  }

  return Object.freeze({
    bytesTransferred,
    totalBytes,
    fraction: totalBytes === 0 ? 1 : bytesTransferred / totalBytes,
  });
}
