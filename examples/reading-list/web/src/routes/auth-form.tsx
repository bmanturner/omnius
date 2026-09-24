import { useLayoutEffect, useRef, useState } from "react";

export interface FragmentSecretState {
  readonly ready: boolean;
  readonly secret: string | null;
  clear(): void;
}

/** Reads a one-time fragment token, then removes the complete fragment before use. */
export function useFragmentSecret(): FragmentSecretState {
  const [secret, setSecret] = useState<string | null>(null);
  const [ready, setReady] = useState(false);
  const consumed = useRef(false);
  useLayoutEffect(() => {
    if (consumed.current) return;
    consumed.current = true;
    const fragment = new URLSearchParams(globalThis.location.hash.slice(1));
    const values = fragment.getAll("token");
    setSecret(values.length === 1 && values[0]?.length !== 0 ? values[0] ?? null : null);
    globalThis.history.replaceState(
      globalThis.history.state,
      "",
      `${globalThis.location.pathname}${globalThis.location.search}`,
    );
    setReady(true);
  }, []);

  return Object.freeze({ ready, secret, clear: () => setSecret(null) });
}
