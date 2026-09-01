import { serviceHttp } from "@omnius/web-sdk/client";
import { useServiceClient } from "@omnius/web-sdk/react";
import { useMutation } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";

import { LoadingState, ProblemState } from "../components/request-states";
import {
  FormProblemSummary,
  mapAuthFormProblem,
  useCoordinatedServiceForm,
  useFragmentSecret,
} from "./auth-form";

interface VerificationRequestFields {
  readonly email: string;
}

export function VerifyEmailRoute() {
  const client = useServiceClient();
  const token = useFragmentSecret("token");
  const submitted = useRef(false);
  const [email, setEmail] = useState("");
  const [resent, setResent] = useState(false);
  const completion = useMutation({
    mutationFn: async (secret: string) =>
      serviceHttp.completeEmailVerification({ token: secret }, client.requestOptions()),
  });
  const resendForm = useCoordinatedServiceForm<
    VerificationRequestFields,
    unknown,
    VerificationRequestFields
  >((error) =>
    mapAuthFormProblem<VerificationRequestFields>(
      error,
      "verification-request",
      ["email"],
      { email: "verification-email" },
    ),
  );
  const problem = resendForm.problem;

  const emailError = problem?.fieldErrors.find((error) => error.path === "email");
  useEffect(() => {
    if (!token.ready || token.secret === null || submitted.current) return;
    submitted.current = true;
    const secret = token.secret;
    token.clear();
    completion.mutate(secret);
  }, [completion, token]);

  const requestAgain = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    void resendForm
      .submit({ email }, (body, signal) =>
        serviceHttp.requestEmailVerification(body, client.requestOptions({ signal })),
      )
      .then((result) => {
        if (result.status === "succeeded") setResent(true);
      });
  };

  if (!token.ready || completion.isPending) return <LoadingState label="Verifying your email" />;
  if (completion.isSuccess) {
    return (
      <section className="state-panel auth-panel" role="status" aria-labelledby="verified-title">
        <h1 id="verified-title">Email verified</h1>
        <p>Your account is active and ready to use.</p>
        <Link className="button-link" to="/login">Sign in</Link>
      </section>
    );
  }

  return (
    <section className="page-section auth-panel" aria-labelledby="verification-title">
      <header className="page-header">
        <p className="eyebrow">Account verification</p>
        <h1 id="verification-title">Request a new verification link</h1>
        <p className="page-intro">Verification links are single-use and expire for your protection.</p>
      </header>
      {completion.isError ? <ProblemState error={completion.error} /> : null}
      {resent ? (
        <div className="state-panel" role="status"><p>If the account can be verified, a new link is on its way.</p></div>
      ) : (
        <form className="record-form panel panel-body" onSubmit={requestAgain} noValidate>
          {problem === null ? null : <FormProblemSummary problem={problem} />}
          {resendForm.error === null ? null : <ProblemState error={resendForm.error} />}
          <label className="field" htmlFor="verification-email">
            Email
            <input
              id="verification-email"
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
          <button className="button-link" type="submit" disabled={resendForm.pending}>
            {resendForm.pending ? "Sending…" : "Send verification link"}
          </button>
        </form>
      )}
    </section>
  );
}
