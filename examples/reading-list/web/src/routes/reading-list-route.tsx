import {
  ServiceProblemError,
  createVersionEntityTag,
  serviceHttp,
  withIfMatch,
} from "@omnius/web-sdk/client";
import {
  serviceQueries,
  useAuthManager,
  useServiceClient,
} from "@omnius/web-sdk/react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";

import type { BrowserSessionAuthManager } from "../auth-manager";
import { EmptyState, LoadingState, ProblemState } from "../components/request-states";

interface ItemDraftErrors {
  readonly title?: string;
  readonly url?: string;
}

class ReadingListConflictError extends Error {
  override readonly name = "ReadingListConflictError";
}

function validateDraft(titleValue: string, urlValue: string): {
  readonly errors: ItemDraftErrors;
  readonly title: string;
  readonly url: string;
} {
  const title = titleValue.trim();
  const titleBytes = new TextEncoder().encode(title).byteLength;
  let canonicalUrl = "";
  let urlError: string | undefined;
  try {
    const parsed = new URL(urlValue.trim());
    if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") || parsed.hostname.length === 0) {
      urlError = "Enter an absolute HTTP or HTTPS URL with a host.";
    } else if (parsed.username.length > 0 || parsed.password.length > 0) {
      urlError = "The URL must not include a username or password.";
    } else {
      canonicalUrl = parsed.toString();
      if (new TextEncoder().encode(canonicalUrl).byteLength > 2_048) {
        urlError = "The URL must be 2,048 bytes or fewer.";
      }
    }
  } catch {
    urlError = "Enter an absolute HTTP or HTTPS URL with a host.";
  }

  return {
    title,
    url: canonicalUrl,
    errors: {
      ...(titleBytes === 0 || titleBytes > 200
        ? { title: "Enter a title between 1 and 200 bytes." }
        : {}),
      ...(urlError === undefined ? {} : { url: urlError }),
    },
  };
}

function conflictStatus(error: unknown): boolean {
  return error instanceof ReadingListConflictError ||
    error instanceof ServiceProblemError && (error.status === 412 || error.status === 428);
}

export function ReadingListRoute() {
  const client = useServiceClient();
  const authManager = useAuthManager() as BrowserSessionAuthManager;
  const navigate = useNavigate({ from: "/" });
  const queryClient = useQueryClient();
  const listKey = serviceQueries.getListReadingItemsQueryKey();
  const list = serviceQueries.useListReadingItems({ request: client.requestOptions() });
  const [title, setTitle] = useState("");
  const [url, setUrl] = useState("");
  const [draftErrors, setDraftErrors] = useState<ItemDraftErrors>({});
  const [announcement, setAnnouncement] = useState("");
  const [actionError, setActionError] = useState<unknown>(null);
  const [conflict, setConflict] = useState(false);
  const [deleteItem, setDeleteItem] = useState<serviceHttp.ReadingItem | null>(null);
  const dialog = useRef<HTMLDialogElement>(null);
  const returnFocus = useRef<HTMLElement | null>(null);
  const listHeading = useRef<HTMLHeadingElement>(null);
  const titleInput = useRef<HTMLInputElement>(null);
  const urlInput = useRef<HTMLInputElement>(null);
  const cancelDeleteButton = useRef<HTMLButtonElement>(null);

  const refreshList = async (): Promise<void> => {
    await queryClient.invalidateQueries({ queryKey: listKey, refetchType: "active" });
  };

  const createItem = useMutation({
    mutationFn: async (draft: { readonly title: string; readonly url: string }) => {
      const response = await serviceHttp.createReadingItem(draft, client.requestOptions());
      if (response.status !== 201) throw new Error("The reading item could not be created.");
      return response.data;
    },
  });
  const updateItem = useMutation({
    mutationFn: async (item: serviceHttp.ReadingItem) => {
      const headers = withIfMatch(undefined, createVersionEntityTag(item.version));
      const response = await serviceHttp.updateReadingItem(
        item.id,
        { finished: !item.finished },
        client.requestOptions({ headers }),
      );
      if (response.status === 412 || response.status === 428) throw new ReadingListConflictError();
      if (response.status !== 200) throw new Error("The reading item could not be updated.");
      return response.data;
    },
  });
  const removeItem = useMutation({
    mutationFn: async (item: serviceHttp.ReadingItem) => {
      const headers = withIfMatch(undefined, createVersionEntityTag(item.version));
      const response = await serviceHttp.deleteReadingItem(
        item.id,
        client.requestOptions({ headers }),
      );
      if (response.status === 412 || response.status === 428) throw new ReadingListConflictError();
      if (response.status !== 204) throw new Error("The reading item could not be deleted.");
      return item;
    },
  });

  useEffect(() => {
    if (!(list.error instanceof ServiceProblemError) || list.error.status !== 401) return;
    void authManager.getSession().then((session) => {
      if (session.status === "anonymous") void navigate({ to: "/login", search: { returnTo: "/" }, replace: true });
    });
  }, [authManager, list.error, navigate]);

  const submitItem = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    if (createItem.isPending) return;
    const draft = validateDraft(title, url);
    setDraftErrors(draft.errors);
    if (Object.keys(draft.errors).length > 0) {
      setAnnouncement("Correct the highlighted fields before adding this item.");
      (draft.errors.title === undefined ? urlInput.current : titleInput.current)?.focus();
      return;
    }
    setActionError(null);
    setConflict(false);
    setAnnouncement("");
    createItem.mutate(
      { title: draft.title, url: draft.url },
      {
        onSuccess: () => {
          setTitle("");
          setUrl("");
          setDraftErrors({});
          setAnnouncement("Reading item added.");
          titleInput.current?.focus();
        },
        onError: (error) => setActionError(error),
        onSettled: () => void refreshList(),
      },
    );
  };

  const toggleItem = (item: serviceHttp.ReadingItem): void => {
    setActionError(null);
    setConflict(false);
    setAnnouncement("");
    updateItem.mutate(item, {
      onSuccess: (updated) => setAnnouncement(updated.finished ? "Marked as finished." : "Marked as unfinished."),
      onError: (error) => {
        if (conflictStatus(error)) {
          setConflict(true);
          setAnnouncement("This item changed elsewhere. The latest list has been loaded; review it and try again.");
        } else {
          setActionError(error);
        }
      },
      onSettled: () => void refreshList(),
    });
  };

  const askToDelete = (item: serviceHttp.ReadingItem, trigger: HTMLElement): void => {
    removeItem.reset();
    returnFocus.current = trigger;
    setDeleteItem(item);
    dialog.current?.showModal();
    queueMicrotask(() => cancelDeleteButton.current?.focus());
  };

  const closeDialog = (): void => {
    dialog.current?.close();
  };

  const restoreDialogFocus = (): void => {
    const target = returnFocus.current;
    setDeleteItem(null);
    if (target?.isConnected === true) target.focus();
    else listHeading.current?.focus();
  };

  const confirmDelete = (): void => {
    if (deleteItem === null || removeItem.isPending) return;
    const item = deleteItem;
    setActionError(null);
    setConflict(false);
    removeItem.mutate(item, {
      onSuccess: () => {
        setAnnouncement(`Deleted ${item.title}.`);
        returnFocus.current = null;
        closeDialog();
      },
      onError: (error) => {
        if (conflictStatus(error)) {
          setConflict(true);
          setAnnouncement("This item changed elsewhere. The latest list has been loaded; review it and try again.");
          returnFocus.current = null;
          closeDialog();
        }
      },
      onSettled: () => void refreshList(),
    });
  };

  const logout = (): void => {
    setActionError(null);
    void authManager
      .logout()
      .then(() => navigate({ to: "/login", replace: true }))
      .catch((error: unknown) => setActionError(error));
  };

  const response = list.data;
  const items = response?.status === 200 ? response.data : undefined;
  const busy = createItem.isPending || updateItem.isPending || removeItem.isPending;

  return (
    <div className="reading-page" aria-busy={busy}>
      <header className="list-header">
        <div>
          <p className="eyebrow">Your quiet corner of the web</p>
          <h1>Reading list</h1>
          <p className="page-intro">Save what matters. Finish it when you are ready.</p>
        </div>
        <button className="button secondary" type="button" onClick={logout}>Sign out</button>
      </header>

      <section className="add-panel" aria-labelledby="add-heading">
        <div>
          <h2 id="add-heading">Add something to read</h2>
          <p>We normalize valid web addresses before saving them.</p>
        </div>
        <form className="add-form" onSubmit={submitItem} noValidate>
          <div>
            <label className="field" htmlFor="reading-title">Title</label>
            <input ref={titleInput} className="input" id="reading-title" value={title} maxLength={200} required aria-invalid={draftErrors.title === undefined ? undefined : true} aria-describedby={draftErrors.title === undefined ? undefined : "reading-title-error"} onChange={(event) => setTitle(event.currentTarget.value)} />
            {draftErrors.title === undefined ? null : <p className="field-error" id="reading-title-error">{draftErrors.title}</p>}
          </div>
          <div>
            <label className="field" htmlFor="reading-url">Web address</label>
            <input ref={urlInput} className="input" id="reading-url" type="url" inputMode="url" placeholder="https://example.com/article" value={url} required aria-invalid={draftErrors.url === undefined ? undefined : true} aria-describedby={draftErrors.url === undefined ? "reading-url-help" : "reading-url-help reading-url-error"} onChange={(event) => setUrl(event.currentTarget.value)} />
            <p className="field-help" id="reading-url-help">Use an absolute HTTP or HTTPS address.</p>
            {draftErrors.url === undefined ? null : <p className="field-error" id="reading-url-error">{draftErrors.url}</p>}
          </div>
          <button className="button primary add-button" type="submit" disabled={createItem.isPending}>{createItem.isPending ? "Adding…" : "Add to list"}</button>
        </form>
      </section>

      <div className="announcements" aria-live="polite" aria-atomic="true">{announcement}</div>
      {conflict ? <div className="conflict-panel" role="alert"><h2>Your list was refreshed</h2><p>This item changed in another session. Review the latest version before trying again.</p></div> : null}
      {actionError === null ? null : <ProblemState error={actionError} />}

      <section className="items-section" aria-labelledby="items-heading">
        <div className="section-heading">
          <h2 id="items-heading" ref={listHeading} tabIndex={-1}>Saved items</h2>
          {items === undefined ? null : <span>{items.length} of 500</span>}
        </div>
        {list.isPending ? <LoadingState label="Loading your reading list" /> : null}
        {list.isError ? (
          <div className="state-with-action">
            <ProblemState error={list.error} />
            <button className="button secondary" type="button" onClick={() => void list.refetch()}>
              Try again
            </button>
          </div>
        ) : null}
        {items?.length === 0 ? <EmptyState title="Your list is empty" detail="Add an article, essay, or book above to begin." /> : null}
        {items === undefined || items.length === 0 ? null : (
          <ul className="reading-items">
            {items.map((item) => (
              <li className="reading-item" data-finished={item.finished} key={item.id}>
                <button className="finish-toggle" type="button" aria-label={`${item.finished ? "Mark as unfinished" : "Mark as finished"}: ${item.title}`} aria-pressed={item.finished} disabled={updateItem.isPending || removeItem.isPending} onClick={() => toggleItem(item)}>
                  <span aria-hidden="true">{item.finished ? "✓" : "○"}</span>
                </button>
                <div className="item-copy">
                  <a href={item.url} target="_blank" rel="noreferrer">{item.title}<span className="visually-hidden"> (opens in a new tab)</span></a>
                  <span className="item-url">{item.url}</span>
                  <span className="finish-label">{item.finished ? "Finished" : "Not finished"}</span>
                </div>
                <button className="delete-button" type="button" aria-label={`Delete ${item.title}`} disabled={removeItem.isPending} onClick={(event) => askToDelete(item, event.currentTarget)}>Delete</button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <dialog
        ref={dialog}
        className="confirm-dialog"
        aria-labelledby="delete-dialog-title"
        aria-describedby="delete-dialog-description"
        onCancel={(event) => {
          if (removeItem.isPending) event.preventDefault();
        }}
        onClose={restoreDialogFocus}
      >
        <h2 id="delete-dialog-title">Delete this item?</h2>
        <p id="delete-dialog-description">{deleteItem === null ? "This cannot be undone." : `“${deleteItem.title}” will be removed from your reading list. This cannot be undone.`}</p>
        {removeItem.isError && !conflictStatus(removeItem.error) ? <ProblemState error={removeItem.error} /> : null}
        <div className="form-actions">
          <button className="button danger" type="button" onClick={confirmDelete} disabled={removeItem.isPending}>{removeItem.isPending ? "Deleting…" : "Delete item"}</button>
          <button ref={cancelDeleteButton} className="button secondary" type="button" onClick={closeDialog} disabled={removeItem.isPending}>Keep item</button>
        </div>
      </dialog>
    </div>
  );
}
