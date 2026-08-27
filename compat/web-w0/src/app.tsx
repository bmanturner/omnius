import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  Outlet,
  RouterProvider,
  createRootRoute,
  createRoute,
  createRouter,
} from "@tanstack/react-router";
import { StrictMode } from "react";

const rootRoute = createRootRoute({
  component: () => <Outlet />,
});

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: () => (
    <main>
      <h1>Omnius web compatibility fixture</h1>
    </main>
  ),
});

const routeTree = rootRoute.addChildren([indexRoute]);
export const router = createRouter({ routeTree });
export const queryClient = new QueryClient();

export function CompatibilityApp() {
  return (
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </StrictMode>
  );
}

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
