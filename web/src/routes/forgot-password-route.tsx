import { ServiceProblemError, serviceHttp } from "@omnius/web-sdk/client";
import { useServiceClient } from "@omnius/web-sdk/react";
import type { ServerFormErrorModel } from "@omnius/web-sdk/react";
import { useMutation } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import type { FormEvent } from "react";

import { ProblemState } from "../components/request-states";
import { FormProblemSummary, mapAuthFormProblem } from "./auth-form";

interface RecoveryFields {
  readonly email: string;
}

export function ForgotPasswordRoute() {
  const client = useServiceClient();
  const [email, setEmail] = useState("");
  const [problem, setProblem] = useState<ServerFormErrorModel<RecoveryFields> | null>(null);
  const requestReset = useMutation({
    mutationFn: async () => serviceHttp.requestPasswordReset({ email }, client.requestOptions()),
    onError: (error) => {
      if (error instanceof ServiceProblemError) {
        setProblem(mapAuthFormProblem<RecoveryFields>(error, "password-recovery", ["email"], {
          email: "recovery-email",
        }));
      }
    },
  });
  const emailError = problem?.fieldErrors.find((error) => error.path === "email");
  const submit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    setProblem(null);
    requestReset.mutate();
  };

  if (requestReset.isSuccess) {
    return (
      <section className="state-panel auth-panel" role="status" aria-labelledby="recovery-sent-title">
        <h1 id="recovery-sent-title">Check your email</h1>
        <p>If the account is eligible, we sent a single-use password reset link.</p>
        <Link className="button-link secondary" to="/login">Return to sign in</Link>
      </section>
    );
  }

  return (
    <section className="page-section auth-panel" aria-labelledby="recovery-title">
      <header className="page-header">
        <p className="eyebrow">Account recovery</p>
        <h1 id="recovery-title">Reset your password</h1>
        <p className="page-intro">Enter the email address associated with your account.</p>
      </header>
      <form className="record-form panel panel-body" onSubmit={submit} noValidate>
        {problem === null ? null : <FormProblemSummary problem={problem} />}
        {requestReset.isError && problem === null ? <ProblemState error={requestReset.error} /> : null}
        <label className="field" htmlFor="recovery-email">
          Email
          <input
            id="recovery-email"
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
        <button className="button-link" type="submit" disabled={requestReset.isPending}>
          {requestReset.isPending ? "Sending…" : "Send reset link"}
        </button>
        <p className="auth-support"><Link to="/login">Return to sign in</Link></p>
      </form>
    </section>
  );
}
