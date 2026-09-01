import { useAuthManager } from "@omnius/web-sdk/react";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { useState } from "react";
import type { FormEvent } from "react";

import type { BrowserSessionAuthManager } from "../auth-manager";
import { ProblemState } from "../components/request-states";
import {
  FormProblemSummary,
  mapAuthFormProblem,
  useCoordinatedServiceForm,
} from "./auth-form";
import { validateReturnTo } from "./route-auth-gate";

interface LoginFields {
  readonly identifier: string;
  readonly password: string;
}

export function LoginRoute() {
  const manager = useAuthManager() as BrowserSessionAuthManager;
  const navigate = useNavigate({ from: "/login" });
  const search = useSearch({ from: "/login" });
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const form = useCoordinatedServiceForm<LoginFields, void, LoginFields>((error) =>
    mapAuthFormProblem<LoginFields>(error, "login", ["identifier", "password"], {
      identifier: "login-identifier",
      password: "login-password",
    }),
  );
  const problem = form.problem;
  const identifierError = problem?.fieldErrors.find((error) => error.path === "identifier");
  const passwordError = problem?.fieldErrors.find((error) => error.path === "password");

  const submit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    void form
      .submit(
        { identifier, password },
        async (credentials, signal) => {
          await manager.login(credentials, { signal });
        },
      )
      .then(async (result) => {
        if (result.status === "succeeded") {
          await navigate({ to: validateReturnTo(search.returnTo), replace: true });
        }
      });
  };

  return (
    <section className="page-section auth-panel" aria-labelledby="login-title">
      <header className="page-header">
        <p className="eyebrow">Account</p>
        <h1 id="login-title">Sign in</h1>
        <p className="page-intro">Continue with your verified Omnius account.</p>
      </header>
      <form className="record-form panel panel-body" onSubmit={submit} noValidate>
        {problem === null ? null : <FormProblemSummary problem={problem} />}
        {form.error === null ? null : <ProblemState error={form.error} />}
        <label className="field" htmlFor="login-identifier">
          Email
          <input
            id="login-identifier"
            className="input"
            type="email"
            name="identifier"
            autoComplete="username"
            required
            value={identifier}
            aria-invalid={identifierError === undefined ? undefined : true}
            aria-describedby={identifierError?.errorId}
            onChange={(event) => setIdentifier(event.currentTarget.value)}
          />
        </label>
        {identifierError === undefined ? null : (
          <p className="field-error" id={identifierError.errorId}>{identifierError.message}</p>
        )}
        <label className="field" htmlFor="login-password">
          Password
          <input
            id="login-password"
            className="input"
            type="password"
            name="password"
            autoComplete="current-password"
            required
            value={password}
            aria-invalid={passwordError === undefined ? undefined : true}
            aria-describedby={passwordError?.errorId}
            onChange={(event) => setPassword(event.currentTarget.value)}
          />
        </label>
        {passwordError === undefined ? null : (
          <p className="field-error" id={passwordError.errorId}>{passwordError.message}</p>
        )}
        <div className="form-actions">
          <button className="button-link" type="submit" disabled={form.pending}>
            {form.pending ? "Signing in…" : "Sign in"}
          </button>
          <Link className="button-link secondary" to="/forgot-password">Forgot password</Link>
        </div>
        <p className="auth-support">New to Omnius? <Link to="/register">Create an account</Link>.</p>
      </form>
    </section>
  );
}
