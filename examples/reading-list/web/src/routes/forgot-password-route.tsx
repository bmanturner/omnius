import { serviceHttp } from "@omnius/web-sdk/client";
import { useServiceClient } from "@omnius/web-sdk/react";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import type { FormEvent } from "react";

import { ProblemState } from "../components/request-states";

export function ForgotPasswordRoute() {
  const client = useServiceClient();
  const [email, setEmail] = useState("");
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
      .requestPasswordReset({ email: email.trim() }, client.requestOptions())
      .then(() => setAccepted(true))
      .catch((failure: unknown) => setError(failure))
      .finally(() => setPending(false));
  };

  if (accepted) {
    return (
      <section className="auth-card success-card" role="status" aria-labelledby="recovery-sent-title">
        <p className="eyebrow">Request received</p>
        <h1 id="recovery-sent-title">Check your email</h1>
        <p>If the account is eligible, a single-use password reset link is on its way.</p>
        <Link className="button secondary" to="/login">Return to sign in</Link>
      </section>
    );
  }

  return (
    <section className="auth-card" aria-labelledby="recovery-title" aria-busy={pending}>
      <header className="page-header compact">
        <p className="eyebrow">Account recovery</p>
        <h1 id="recovery-title">Reset your password</h1>
        <p className="page-intro">Enter the email address associated with your account.</p>
      </header>
      {error === null ? null : <ProblemState error={error} />}
      <form className="form-stack" onSubmit={submit}>
        <label className="field" htmlFor="recovery-email">
          Email address
          <input className="input" id="recovery-email" type="email" autoComplete="email" required value={email} onChange={(event) => setEmail(event.currentTarget.value)} />
        </label>
        <button className="button primary" type="submit" disabled={pending}>{pending ? "Sending…" : "Send reset link"}</button>
      </form>
      <p className="auth-support"><Link to="/login">Return to sign in</Link></p>
    </section>
  );
}
