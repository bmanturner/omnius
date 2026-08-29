import { ServiceProblemError, serviceHttp } from "@omnius/web-sdk/client";
import { useServiceClient } from "@omnius/web-sdk/react";
import type { ServerFormErrorModel } from "@omnius/web-sdk/react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import type { FormEvent } from "react";

import { ProblemState } from "../components/request-states";
import { FormProblemSummary, mapAuthFormProblem } from "./auth-form";

interface PasswordChangeFields {
  readonly current_password: string;
  readonly new_password: string;
}

export function AccountSecurityRoute() {
  const client = useServiceClient();
  const queryClient = useQueryClient();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [problem, setProblem] = useState<ServerFormErrorModel<PasswordChangeFields> | null>(null);
  const changePassword = useMutation({
    mutationFn: async () => serviceHttp.changePassword(
      { current_password: currentPassword, new_password: newPassword },
      client.requestOptions(),
    ),
    onSuccess: async () => {
      setCurrentPassword("");
      setNewPassword("");
      await queryClient.invalidateQueries();
    },
    onError: (error) => {
      if (error instanceof ServiceProblemError) {
        setProblem(mapAuthFormProblem<PasswordChangeFields>(
          error,
          "password-change",
          ["current_password", "new_password"],
          {
            current_password: "current-password",
            new_password: "new-password",
          },
        ));
      }
    },
  });
  const currentPasswordError = problem?.fieldErrors.find((error) => error.path === "current_password");
  const newPasswordError = problem?.fieldErrors.find((error) => error.path === "new_password");
  const submit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    setProblem(null);
    changePassword.mutate();
  };

  return (
    <section className="page-section auth-panel" aria-labelledby="security-title">
      <header className="page-header">
        <p className="eyebrow">Account security</p>
        <h1 id="security-title">Change password</h1>
        <p className="page-intro">Changing your password signs out your other browser sessions.</p>
      </header>
      {changePassword.isSuccess ? (
        <div className="state-panel success-panel" role="status"><p>Your password was updated.</p></div>
      ) : null}
      <form className="record-form panel panel-body" onSubmit={submit} noValidate>
        {problem === null ? null : <FormProblemSummary problem={problem} />}
        {changePassword.isError && problem === null ? <ProblemState error={changePassword.error} /> : null}
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
        <button className="button-link" type="submit" disabled={changePassword.isPending}>
          {changePassword.isPending ? "Updating…" : "Update password"}
        </button>
      </form>
    </section>
  );
}
