import { createContext, useContext, type ReactNode } from "react";

export interface WebApplicationContributions {
  readonly uploads?: unknown;
}

interface WebRuntimeCompositionValue {
  readonly contributions: Readonly<WebApplicationContributions>;
  readonly realtimeManager: unknown | null;
}

const WebRuntimeCompositionContext = createContext<WebRuntimeCompositionValue | null>(null);

export interface WebRuntimeCompositionProviderProps extends WebRuntimeCompositionValue {
  readonly children?: ReactNode;
}

export function WebRuntimeCompositionProvider({
  children,
  contributions,
  realtimeManager,
}: WebRuntimeCompositionProviderProps) {
  return (
    <WebRuntimeCompositionContext.Provider value={{ contributions, realtimeManager }}>
      {children}
    </WebRuntimeCompositionContext.Provider>
  );
}

export function useWebRuntimeComposition(): WebRuntimeCompositionValue {
  const composition = useContext(WebRuntimeCompositionContext);
  if (composition === null) {
    throw new Error("Web runtime composition hooks require WebRuntimeCompositionProvider.");
  }
  return composition;
}
