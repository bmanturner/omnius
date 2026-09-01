import { serviceHttp } from "@omnius/web-sdk/client";
import { useServiceClient } from "@omnius/web-sdk/react";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import type { FormEvent } from "react";

import { ProblemState } from "../components/request-states";
import {
  FormProblemSummary,
  mapAuthFormProblem,
  useCoordinatedServiceForm,
} from "./auth-form";

interface PasswordChangeFields {
  readonly current_password: string;
  readonly new_password: string;
}

export function AccountSecurityRoute() {
  const client = useServiceClient();
  const queryClient = useQueryClient();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [succeeded, setSucceeded] = useState(false);
  const form = useCoordinatedServiceForm<
    PasswordChangeFields,
    unknown,
    PasswordChangeFields
  >((error) =>
    mapAuthFormProblem<PasswordChangeFields>(
      error,
      "password-change",
      ["current_password", "new_password"],
      {
        current_password: "current-password",
        new_password: "new-password",
      },
    ),
  );
  const problem = form.problem;
  const currentPasswordError = problem?.fieldErrors.find((error) => error.path === "current_password");
  const newPasswordError = problem?.fieldErrors.find((error) => error.path === "new_password");
  const submit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    setSucceeded(false);
    void form
      .submit(
        { current_password: currentPassword, new_password: newPassword },
        (body, signal) => serviceHttp.changePassword(body, client.requestOptions({ signal })),
      )
      .then(async (result) => {
        if (result.status !== "succeeded") return;
        setCurrentPassword("");
        setNewPassword("");
        setSucceeded(true);
        await queryClient.invalidateQueries();
      });
  };

  return (
    <section className="page-section auth-panel" aria-labelledby="security-title">
      <header className="page-header">
        <p className="eyebrow">Account security</p>
        <h1 id="security-title">Change password</h1>
        <p className="page-intro">Changing your password signs out your other browser sessions.</p>
      </header>
      {succeeded ? (
        <div className="state-panel success-panel" role="status"><p>Your password was updated.</p></div>
      ) : null}
      <form className="record-form panel panel-body" onSubmit={submit} noValidate>
        {problem === null ? null : <FormProblemSummary problem={problem} />}
        {form.error === null ? null : <ProblemState error={form.error} />}
        <label className="field" htmlFor="current-password">
          Current password
          <input
            id="current-password"
            className="input"
            type="password"
            name="current_password"
            autoComplete="current-password"
            required
            value={currentPassword}
            aria-invalid={currentPasswordError === undefined ? undefined : true}
            aria-describedby={currentPasswordError?.errorId}
            onChange={(event) => setCurrentPassword(event.currentTarget.value)}
          />
        </label>
        {currentPasswordError === undefined ? null : (
          <p className="field-error" id={currentPasswordError.errorId}>{currentPasswordError.message}</p>
        )}
        <label className="field" htmlFor="new-password">
          New password
          <input
            id="new-password"
            className="input"
            type="password"
            name="new_password"
            autoComplete="new-password"
            minLength={12}
            required
            value={newPassword}
            aria-invalid={newPasswordError === undefined ? undefined : true}
            aria-describedby={newPasswordError?.errorId ?? "new-password-help"}
            onChange={(event) => setNewPassword(event.currentTarget.value)}
          />
        </label>
        <p className="field-help" id="new-password-help">Use at least 12 characters.</p>
        {newPasswordError === undefined ? null : (
          <p className="field-error" id={newPasswordError.errorId}>{newPasswordError.message}</p>
        )}
        <button className="button-link" type="submit" disabled={form.pending}>
          {form.pending ? "Updating…" : "Update password"}
        </button>
      </form>
    </section>
  );
}
