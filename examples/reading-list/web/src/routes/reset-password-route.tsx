import { serviceHttp } from "@omnius/web-sdk/client";
import { useServiceClient } from "@omnius/web-sdk/react";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import type { FormEvent } from "react";

import { LoadingState, ProblemState } from "../components/request-states";
import { useFragmentSecret } from "./auth-form";

export function ResetPasswordRoute() {
  const client = useServiceClient();
  const token = useFragmentSecret();
  const [password, setPassword] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [pending, setPending] = useState(false);
  const [complete, setComplete] = useState(false);

  const submit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    const form = event.currentTarget;
    if (!form.reportValidity() || token.secret === null || pending) return;
    const secret = token.secret;
    token.clear();
    setPending(true);
    setError(null);
    void serviceHttp
      .completePasswordReset(
        { token: secret, new_password: password },
        client.requestOptions(),
      )
      .then(() => setComplete(true))
      .catch((failure: unknown) => setError(failure))
      .finally(() => setPending(false));
  };

  if (!token.ready) return <LoadingState label="Preparing password reset" />;
  if (complete) {
    return (
      <section className="auth-card success-card" role="status" aria-labelledby="reset-complete-title">
        <p className="eyebrow">Password updated</p>
        <h1 id="reset-complete-title">Your password has been reset</h1>
        <p>Other browser sessions were signed out. Sign in with your new password.</p>
        <Link className="button primary" to="/login">Sign in</Link>
      </section>
    );
  }
  if (token.secret === null && !pending) {
    return (
      <section className="auth-card" role="alert" aria-labelledby="reset-unavailable-title">
        <h1 id="reset-unavailable-title">
          {error === null ? "Reset link unavailable" : "We could not reset your password"}
        </h1>
        {error === null ? (
          <p>This link is missing its one-time token or was already consumed in this browser.</p>
        ) : (
          <ProblemState error={error} />
        )}
        <Link className="button secondary" to="/forgot-password">Request another link</Link>
      </section>
    );
  }

  return (
    <section className="auth-card" aria-labelledby="reset-title" aria-busy={pending}>
      <header className="page-header compact">
        <p className="eyebrow">Account recovery</p>
        <h1 id="reset-title">Choose a new password</h1>
        <p className="page-intro">Your reset link is single-use.</p>
      </header>
      {error === null ? null : <ProblemState error={error} />}
      <form className="form-stack" onSubmit={submit}>
        <label className="field" htmlFor="reset-password">
          New password
          <input className="input" id="reset-password" type="password" autoComplete="new-password" minLength={12} required aria-describedby="reset-password-help" value={password} onChange={(event) => setPassword(event.currentTarget.value)} />
        </label>
        <p className="field-help" id="reset-password-help">Use at least 12 characters.</p>
        <button className="button primary" type="submit" disabled={pending}>{pending ? "Updating…" : "Update password"}</button>
      </form>
    </section>
  );
}
