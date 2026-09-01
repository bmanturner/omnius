import { serviceHttp } from "@omnius/web-sdk/client";
import { useServiceClient } from "@omnius/web-sdk/react";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import type { FormEvent } from "react";

import { ProblemState } from "../components/request-states";
import {
  FormProblemSummary,
  mapAuthFormProblem,
  useCoordinatedServiceForm,
  useFragmentSecret,
} from "./auth-form";

interface RegisterFields {
  readonly email: string;
  readonly password: string;
  readonly invitation: string;
}

export function RegisterRoute() {
  const client = useServiceClient();
  const invitation = useFragmentSecret("invitation");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [succeeded, setSucceeded] = useState(false);
  const form = useCoordinatedServiceForm<
    serviceHttp.AccountRegisterRequestSchema,
    unknown,
    RegisterFields
  >((error) =>
    mapAuthFormProblem<RegisterFields>(
      error,
      "register",
      ["email", "password", "invitation"],
      { email: "register-email", password: "register-password" },
    ),
  );
  const problem = form.problem;
  const emailError = problem?.fieldErrors.find((error) => error.path === "email");
  const passwordError = problem?.fieldErrors.find((error) => error.path === "password");

  const submit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    if (!invitation.ready || form.pending || succeeded) return;
    const secret = invitation.secret;
    invitation.clear();
    void form
      .submit(
        {
          email,
          password,
          ...(secret === null ? {} : { invitation: secret }),
        },
        (body, signal) =>
          serviceHttp.registerLocalAccount(body, client.requestOptions({ signal })),
      )
      .then((result) => {
        if (result.status === "succeeded") setSucceeded(true);
      });
  };

  if (succeeded) {
    return (
      <section className="state-panel auth-panel" role="status" aria-labelledby="registration-sent-title">
        <h1 id="registration-sent-title">Check your email</h1>
        <p>If registration is available, we sent instructions to verify the account.</p>
        <Link className="button-link secondary" to="/login">Return to sign in</Link>
      </section>
    );
  }

  return (
    <section className="page-section auth-panel" aria-labelledby="register-title">
      <header className="page-header">
        <p className="eyebrow">New account</p>
        <h1 id="register-title">Create your account</h1>
        <p className="page-intro">Your account becomes active after email verification.</p>
      </header>
      <form className="record-form panel panel-body" onSubmit={submit} noValidate>
        {problem === null ? null : <FormProblemSummary problem={problem} />}
        {form.error === null ? null : <ProblemState error={form.error} />}
        <label className="field" htmlFor="register-email">
          Email
          <input
            id="register-email"
            className="input"
            type="email"
            name="email"
            autoComplete="email"
            required
            value={email}
            aria-invalid={emailError === undefined ? undefined : true}
            aria-describedby={emailError?.errorId}
            onChange={(event) => setEmail(event.currentTarget.value)}
          />
        </label>
        {emailError === undefined ? null : (
          <p className="field-error" id={emailError.errorId}>{emailError.message}</p>
        )}
        <label className="field" htmlFor="register-password">
          Password
          <input
            id="register-password"
            className="input"
            type="password"
            name="password"
            autoComplete="new-password"
            required
            minLength={12}
            value={password}
            aria-invalid={passwordError === undefined ? undefined : true}
            aria-describedby={passwordError?.errorId ?? "register-password-help"}
            onChange={(event) => setPassword(event.currentTarget.value)}
          />
        </label>
        <p className="field-help" id="register-password-help">Use at least 12 characters.</p>
        {passwordError === undefined ? null : (
          <p className="field-error" id={passwordError.errorId}>{passwordError.message}</p>
        )}
        <button className="button-link" type="submit" disabled={!invitation.ready || form.pending}>
          {form.pending ? "Creating account…" : "Create account"}
        </button>
        <p className="auth-support">Already registered? <Link to="/login">Sign in</Link>.</p>
      </form>
    </section>
  );
}
