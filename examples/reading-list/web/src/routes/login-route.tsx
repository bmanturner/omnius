import { useAuthManager } from "@omnius/web-sdk/react";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import type { FormEvent } from "react";

import type { BrowserSessionAuthManager } from "../auth-manager";
import { ProblemState } from "../components/request-states";

export function LoginRoute() {
  const manager = useAuthManager() as BrowserSessionAuthManager;
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [pending, setPending] = useState(false);

  const submit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    const form = event.currentTarget;
    if (!form.reportValidity() || pending) return;
    setPending(true);
    setError(null);
    void manager
      .login({ identifier: identifier.trim(), password })
      .catch((failure: unknown) => setError(failure))
      .finally(() => setPending(false));
  };

  return (
    <section className="auth-card" aria-labelledby="login-title" aria-busy={pending}>
      <header className="page-header compact">
        <p className="eyebrow">Welcome back</p>
        <h1 id="login-title">Sign in to Reading List</h1>
        <p className="page-intro">Continue with your verified account.</p>
      </header>
      {error === null ? null : <ProblemState error={error} />}
      <form className="form-stack" onSubmit={submit}>
        <label className="field" htmlFor="login-email">
          Email address
          <input
            className="input"
            id="login-email"
            type="email"
            autoComplete="username"
            required
            value={identifier}
            onChange={(event) => setIdentifier(event.currentTarget.value)}
          />
        </label>
        <label className="field" htmlFor="login-password">
          Password
          <input
            className="input"
            id="login-password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(event) => setPassword(event.currentTarget.value)}
          />
        </label>
        <div className="form-actions split-actions">
          <button className="button primary" type="submit" disabled={pending}>
            {pending ? "Signing in…" : "Sign in"}
          </button>
          <Link to="/forgot-password">Forgot password?</Link>
        </div>
      </form>
      <p className="auth-support">New here? <Link to="/register">Create an account</Link>.</p>
    </section>
  );
}
