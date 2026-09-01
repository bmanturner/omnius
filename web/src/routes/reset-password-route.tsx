import { serviceHttp } from "@omnius/web-sdk/client";
import { useServiceClient } from "@omnius/web-sdk/react";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import type { FormEvent } from "react";

import { LoadingState, ProblemState } from "../components/request-states";
import {
  FormProblemSummary,
  mapAuthFormProblem,
  useCoordinatedServiceForm,
  useFragmentSecret,
} from "./auth-form";

interface ResetFields {
  readonly new_password: string;
  readonly token: string;
}

export function ResetPasswordRoute() {
  const client = useServiceClient();
  const token = useFragmentSecret("token");
  const [password, setPassword] = useState("");
  const [succeeded, setSucceeded] = useState(false);
  const form = useCoordinatedServiceForm<
    serviceHttp.AccountPasswordResetRequestSchema,
    unknown,
    ResetFields
  >((error) =>
    mapAuthFormProblem<ResetFields>(
      error,
      "password-reset",
      ["new_password", "token"],
      { new_password: "reset-password" },
    ),
  );
  const problem = form.problem;
  const passwordError = problem?.fieldErrors.find((error) => error.path === "new_password");
  const submit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    if (token.secret === null || form.pending || succeeded) return;
    const secret = token.secret;
    token.clear();
    void form
      .submit(
        { new_password: password, token: secret },
        (body, signal) =>
          serviceHttp.completePasswordReset(body, client.requestOptions({ signal })),
      )
      .then((result) => {
        if (result.status === "succeeded") setSucceeded(true);
      });
  };

  if (!token.ready) return <LoadingState label="Preparing password reset" />;
  if (succeeded) {
    return (
      <section className="state-panel auth-panel" role="status" aria-labelledby="reset-complete-title">
        <h1 id="reset-complete-title">Password updated</h1>
        <p>Your other browser sessions have been signed out.</p>
        <Link className="button-link" to="/login">Sign in with your new password</Link>
      </section>
    );
  }
  if (token.secret === null && !form.pending && problem === null && form.error === null) {
    return (
      <section className="state-panel auth-panel" data-tone="error" role="alert">
        <h1>Reset link unavailable</h1>
        <p>This reset link is missing or has already been used in this browser.</p>
        <Link className="button-link secondary" to="/forgot-password">Request another link</Link>
      </section>
    );
  }

  return (
    <section className="page-section auth-panel" aria-labelledby="reset-title">
      <header className="page-header">
        <p className="eyebrow">Account recovery</p>
        <h1 id="reset-title">Choose a new password</h1>
        <p className="page-intro">This single-use link will be consumed when you save.</p>
      </header>
      <form className="record-form panel panel-body" onSubmit={submit} noValidate>
        {problem === null ? null : <FormProblemSummary problem={problem} />}
        {form.error === null ? null : <ProblemState error={form.error} />}
        <label className="field" htmlFor="reset-password">
          New password
          <input
            id="reset-password"
            className="input"
            type="password"
            name="new_password"
            autoComplete="new-password"
            minLength={12}
            required
            value={password}
            aria-invalid={passwordError === undefined ? undefined : true}
            aria-describedby={passwordError?.errorId ?? "reset-password-help"}
            onChange={(event) => setPassword(event.currentTarget.value)}
          />
        </label>
        <p className="field-help" id="reset-password-help">Use at least 12 characters.</p>
        {passwordError === undefined ? null : (
          <p className="field-error" id={passwordError.errorId}>{passwordError.message}</p>
        )}
        <button className="button-link" type="submit" disabled={form.pending || token.secret === null}>
          {form.pending ? "Updating…" : "Update password"}
        </button>
      </form>
    </section>
  );
}
