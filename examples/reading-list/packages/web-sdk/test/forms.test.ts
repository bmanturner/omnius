import { z } from "zod";
import { describe, expect, it } from "vitest";

import {
  applyServerFormErrors,
  createFormSubmissionCoordinator,
  formFieldControlId,
  inspectZodClientHints,
  mapFormProblem,
} from "../src/react/forms.js";
import type {
  FormProblemDetails,
  ReactHookFormErrorSink,
  ServerFormErrorModel,
} from "../src/react/forms.js";

type ProfileForm = {
  profile: { displayName: string };
  contacts: Array<{ email: string }>;
};

const profileProblem: FormProblemDetails = {
  status: 422,
  type: "https://problems.example/validation",
  code: "validation_failed",
  title: "Validation failed",
  detail: "Correct the highlighted fields.",
  requestId: "req-7f3a",
  fieldViolations: [
    { code: "too_short", message: "Enter a display name.", pointer: "/profile/displayName" },
    { code: "invalid_email", message: "Enter a valid email.", pointer: "/contacts/0/email" },
  ],
};

function mappedProfileProblem(): ServerFormErrorModel<ProfileForm> {
  return mapFormProblem<ProfileForm>(profileProblem, {
    formId: "profile-form",
    knownFields: ["profile.displayName", "contacts.0.email"],
  });
}

describe("RFC 9457 form mapping", () => {
  it("maps nested and array pointers to typed field paths", () => {
    const model = mappedProfileProblem();

    expect(model.fieldErrors.map(({ path }) => path)).toEqual([
      "profile.displayName",
      "contacts.0.email",
    ]);
    expect(model.fieldErrors[1]).toMatchObject({
      path: "contacts.0.email",
      code: "invalid_email",
      controlId: "profile_002d_form--field--contacts_002e_0_002e_email",
      errorId: "profile_002d_form--field--contacts_002e_0_002e_email--server-error",
    });
  });

  it("preserves the problem-level error and moves unknown or global violations to the summary", () => {
    const model = mapFormProblem<ProfileForm>(
      {
        ...profileProblem,
        fieldViolations: [
          { code: "unknown", message: "A newer field was rejected.", pointer: "/newField" },
          { code: "global", message: "The values conflict.", pointer: "" },
          { code: "unsafe", message: "Unsafe path.", pointer: "/__proto__/polluted" },
        ],
      },
      {
        formId: "profile-form",
        knownFields: ["profile.displayName", "contacts.0.email"],
      },
    );

    expect(model.fieldErrors).toEqual([]);
    expect(model.globalErrors).toEqual([
      { code: "validation_failed", message: "Correct the highlighted fields." },
      { code: "unknown", message: "A newer field was rejected.", pointer: "/newField" },
      { code: "global", message: "The values conflict.", pointer: "" },
      { code: "unsafe", message: "Unsafe path.", pointer: "/__proto__/polluted" },
    ]);
    expect(model.summary.items).toHaveLength(4);
  });

  it("carries request metadata and produces accessible summary links and focus guidance", () => {
    const model = mappedProfileProblem();
    const emailItem = model.summary.items.find(({ path }) => path === "contacts.0.email");

    expect(model.support).toEqual({
      status: 422,
      problemType: "https://problems.example/validation",
      problemCode: "validation_failed",
      requestId: "req-7f3a",
      requestIdLabel: "Request ID",
    });
    expect(model.summary).toMatchObject({
      id: "profile_002d_form--error-summary",
      headingId: "profile_002d_form--error-summary--heading",
      role: "alert",
      ariaLive: "polite",
      tabIndex: -1,
    });
    expect(emailItem).toMatchObject({
      path: "contacts.0.email",
      href: "#profile_002d_form--field--contacts_002e_0_002e_email",
    });
    expect(model.focus).toEqual({
      target: "summary",
      id: "profile_002d_form--error-summary",
      firstField: "profile.displayName",
    });
  });

  it("generates distinct safe IDs for delimiter and escape-like field names", () => {
    expect(formFieldControlId("profile", "tax%rate")).not.toBe(
      formFieldControlId("profile", "tax_25rate"),
    );
    expect(formFieldControlId("profile", "a--b")).not.toBe(
      formFieldControlId("profile", "a.b"),
    );
  });

  it("applies backend errors after client hints so backend messages take precedence", () => {
    const errors = new Map<string, { readonly type?: string; readonly message?: string }>([
      ["profile.displayName", { type: "client.too_small", message: "Client hint." }],
    ]);
    const sink: ReactHookFormErrorSink<ProfileForm> = {
      setError: ((name: string, error: { readonly type?: string; readonly message?: string }) => {
        errors.set(name, error);
      }) as ReactHookFormErrorSink<ProfileForm>["setError"],
      clearErrors: (() => undefined) as ReactHookFormErrorSink<ProfileForm>["clearErrors"],
    };

    applyServerFormErrors(mappedProfileProblem(), sink);

    expect(errors.get("profile.displayName")).toEqual({
      type: "server.too_short",
      message: "Enter a display name.",
    });
    expect(errors.get("root.server")?.message).toBe("Correct the highlighted fields.");
  });
});

describe("Zod client hints", () => {
  it("preserves contract input and exposes successful transformations separately", () => {
    const schema = z
      .object({ displayName: z.string() })
      .transform(({ displayName }) => ({ displayName: displayName.trim() }));
    const input = { displayName: "  Ada  " };

    const inspected = inspectZodClientHints(schema, input);

    expect(inspected.contractInput).toBe(input);
    expect(inspected).toMatchObject({
      acceptedByClientHint: true,
      transformed: { displayName: "Ada" },
      hints: [],
    });
  });

  it("reports non-authoritative nested hints without replacing the original input", () => {
    const schema = z.object({ contacts: z.array(z.object({ email: z.email() })) });
    const input = { contacts: [{ email: "not-an-email" }] };

    const inspected = inspectZodClientHints(schema, input);

    expect(inspected.contractInput).toBe(input);
    expect(inspected).toMatchObject({
      acceptedByClientHint: false,
      hints: [{ path: "contacts.0.email" }],
    });
  });
});

describe("form submission coordinator", () => {
  it("rejects a double submission while the first request is in flight", async () => {
    let resolveRequest: ((value: string) => void) | undefined;
    const request = new Promise<string>((resolve) => {
      resolveRequest = resolve;
    });
    const coordinator = createFormSubmissionCoordinator<string, string, FormProblemDetails, string>(
      {
        getServerProblem: () => undefined,
        applyServerProblem: () => "server-errors",
        clearServerErrors: () => undefined,
      },
    );

    const first = coordinator.submit("first", async () => request);
    const second = await coordinator.submit("second", async () => "unexpected");
    resolveRequest?.("saved");

    await expect(first).resolves.toEqual({ status: "succeeded", value: "saved" });
    expect(second).toEqual({ status: "busy" });
  });

  it("forwards cancellation and disposes without accepting another request", async () => {
    let observedSignal: AbortSignal | undefined;
    const coordinator = createFormSubmissionCoordinator<string, string, FormProblemDetails, string>(
      {
        getServerProblem: () => undefined,
        applyServerProblem: () => "server-errors",
        clearServerErrors: () => undefined,
      },
    );
    const inFlight = coordinator.submit(
      "value",
      async (_input, signal) =>
        new Promise<string>((_resolve, reject) => {
          observedSignal = signal;
          signal.addEventListener("abort", () => reject(signal.reason), { once: true });
        }),
    );

    expect(coordinator.cancel("cancelled by user")).toBe(true);
    await expect(inFlight).resolves.toEqual({ status: "cancelled" });
    expect(observedSignal?.aborted).toBe(true);

    coordinator.dispose();
    await expect(coordinator.submit("again", async () => "saved")).resolves.toEqual({
      status: "disposed",
    });
  });

  it("reconciles prior server errors and gives a received backend rejection precedence", async () => {
    const cleared: Array<string | undefined> = [];
    const rejectedProblem = { ...profileProblem, code: "backend_rejection" };
    const coordinator = createFormSubmissionCoordinator<
      string,
      string,
      FormProblemDetails,
      string
    >({
      getServerProblem: (error) =>
        error === rejectedProblem ? rejectedProblem : undefined,
      applyServerProblem: (problem) => `model:${problem.code}`,
      clearServerErrors: (previous) => cleared.push(previous),
    });

    const abortController = new AbortController();
    const rejected = await coordinator.submit(
      "first",
      async () => {
        abortController.abort();
        throw rejectedProblem;
      },
      abortController.signal,
    );
    const succeeded = await coordinator.submit("second", async () => "saved");

    expect(rejected).toEqual({ status: "rejected", model: "model:backend_rejection" });
    expect(succeeded).toEqual({ status: "succeeded", value: "saved" });
    expect(cleared).toEqual([undefined, "model:backend_rejection"]);
  });
});
