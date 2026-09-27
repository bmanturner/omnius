import { serviceHttp } from "@omnius/web-sdk/client";
import { useServiceClient } from "@omnius/web-sdk/react";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import type { FormEvent } from "react";

import { ProblemState } from "../components/request-states";

export function RegisterRoute() {
  const client = useServiceClient();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [pending, setPending] = useState(false);
  const [accepted, setAccepted] = useState(false);

  const submit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    const form = event.currentTarget;
    if (!form.reportValidity() || pending) return;
    setPending(true);
    setError(null);
    void serviceHttp
      .registerLocalAccount(
        { email: email.trim(), password },
        client.requestOptions(),
      )
      .then(() => setAccepted(true))
      .catch((failure: unknown) => setError(failure))
      .finally(() => setPending(false));
  };

  if (accepted) {
    return (
      <section className="auth-card success-card" role="status" aria-labelledby="registration-title">
        <p className="eyebrow">One more step</p>
        <h1 id="registration-title">Check your email</h1>
        <p>We sent verification instructions if the address can be registered. Open the link before signing in.</p>
        <Link className="button secondary" to="/login">Return to sign in</Link>
      </section>
    );
  }

  return (
    <section className="auth-card" aria-labelledby="register-title" aria-busy={pending}>
      <header className="page-header compact">
        <p className="eyebrow">Start collecting</p>
        <h1 id="register-title">Create your account</h1>
        <p className="page-intro">Your private list is ready after email verification.</p>
      </header>
      {error === null ? null : <ProblemState error={error} />}
      <form className="form-stack" onSubmit={submit}>
        <label className="field" htmlFor="register-email">
          Email address
          <input className="input" id="register-email" type="email" autoComplete="email" required value={email} onChange={(event) => setEmail(event.currentTarget.value)} />
        </label>
        <label className="field" htmlFor="register-password">
          Password
          <input className="input" id="register-password" type="password" autoComplete="new-password" minLength={12} required aria-describedby="register-password-help" value={password} onChange={(event) => setPassword(event.currentTarget.value)} />
        </label>
        <p className="field-help" id="register-password-help">Use at least 12 characters.</p>
        <button className="button primary" type="submit" disabled={pending}>{pending ? "Creating account…" : "Create account"}</button>
      </form>
      <p className="auth-support">Already registered? <Link to="/login">Sign in</Link>.</p>
    </section>
  );
}
