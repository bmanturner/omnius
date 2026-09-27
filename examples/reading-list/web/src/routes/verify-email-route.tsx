import { serviceHttp } from "@omnius/web-sdk/client";
import { useServiceClient } from "@omnius/web-sdk/react";
import { Link } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";

import { LoadingState, ProblemState } from "../components/request-states";
import { useFragmentSecret } from "./auth-form";

export function VerifyEmailRoute() {
  const client = useServiceClient();
  const token = useFragmentSecret();
  const submitted = useRef(false);
  const [status, setStatus] = useState<"waiting" | "submitting" | "complete" | "failed">("waiting");
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    if (!token.ready || token.secret === null || submitted.current) return;
    submitted.current = true;
    setStatus("submitting");
    const secret = token.secret;
    token.clear();
    void serviceHttp
      .completeEmailVerification({ token: secret }, client.requestOptions())
      .then(() => setStatus("complete"))
      .catch((failure: unknown) => {
        setError(failure);
        setStatus("failed");
      });
  }, [client, token]);

  if (!token.ready || (status === "waiting" && token.secret !== null) || status === "submitting") {
    return <LoadingState label="Verifying your email" />;
  }
  if (status === "complete") {
    return (
      <section className="auth-card success-card" role="status" aria-labelledby="verified-title">
        <p className="eyebrow">Verification complete</p>
        <h1 id="verified-title">Your email is verified</h1>
        <p>Your private reading list is ready.</p>
        <Link className="button primary" to="/login">Sign in</Link>
      </section>
    );
  }
  if (status === "failed") {
    return (
      <section className="auth-card" aria-labelledby="verification-failed-title">
        <h1 id="verification-failed-title">We could not verify this link</h1>
        {error === null ? null : <ProblemState error={error} />}
        <p>The link may be expired or already used. Register again to receive a fresh verification message.</p>
        <Link className="button secondary" to="/register">Return to registration</Link>
      </section>
    );
  }
  return (
    <section className="auth-card" role="alert" aria-labelledby="verification-missing-title">
      <h1 id="verification-missing-title">Verification link unavailable</h1>
      <p>This link is missing its one-time token. Open the complete link from your email.</p>
      <Link className="button secondary" to="/login">Return to sign in</Link>
    </section>
  );
}
