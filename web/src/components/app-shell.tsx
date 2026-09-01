import {
  useCapabilityRegistry,
  useCompiledCapability,
  useContractMismatch,
  useRuntimeCapability,
  useSession,
} from "@omnius/web-sdk/react";
import { Link, Outlet, useRouterState } from "@tanstack/react-router";
import { useEffect, useRef } from "react";

import { BUILD_METADATA } from "../build-metadata";

function titleForPath(pathname: string): string {
  if (pathname === "/") {
    return "Service overview · Omnius";
  }
  if (pathname === "/records") {
    return "Reference records · Omnius";
  }
  const routeTitles: Readonly<Record<string, string>> = {
    "/account": "Account · Omnius",
    "/account/api-keys": "API keys · Omnius",
    "/account/connected-apps": "Connected applications · Omnius",
    "/account/security": "Account security · Omnius",
    "/account/sessions": "Browser sessions · Omnius",
    "/authorize": "Authorize application · Omnius",
    "/forgot-password": "Reset password · Omnius",
    "/login": "Sign in · Omnius",
    "/register": "Create account · Omnius",
    "/reset-password": "Choose a new password · Omnius",
    "/verify-email": "Verify email · Omnius",
  };
  return routeTitles[pathname] ?? "Page not found · Omnius";
}

function AuthenticatedAccountNavigation() {
  const session = useSession().data;
  if (session?.status !== "authenticated") return null;
  return (
    <>
      <li>
        <Link
          className="nav-link"
          to="/account"
          activeOptions={{ exact: true }}
          activeProps={{ "aria-current": "page" }}
        >
          Account
        </Link>
      </li>
      <li>
        <Link className="nav-link" to="/account/security" activeProps={{ "aria-current": "page" }}>
          Security
        </Link>
      </li>
      <li>
        <Link className="nav-link" to="/account/sessions" activeProps={{ "aria-current": "page" }}>
          Sessions
        </Link>
      </li>
      <li>
        <Link className="nav-link" to="/account/api-keys" activeProps={{ "aria-current": "page" }}>
          API keys
        </Link>
      </li>
      <li>
        <Link className="nav-link" to="/account/connected-apps" activeProps={{ "aria-current": "page" }}>
          Connected apps
        </Link>
      </li>
    </>
  );
}

function OptionalAccountNavigation() {
  const registry = useCapabilityRegistry();
  const compiled = useCompiledCapability(registry, "web-auth");
  const runtime = useRuntimeCapability(registry, "web-auth");
  return compiled.compiled && runtime.available ? <AuthenticatedAccountNavigation /> : null;
}

export function AppShell() {
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const mismatch = useContractMismatch();
  const mainContent = useRef<HTMLElement>(null);
  const previousPathname = useRef(pathname);

  useEffect(() => {
    document.title = titleForPath(pathname);
    if (pathname !== previousPathname.current) {
      previousPathname.current = pathname;
      mainContent.current?.focus();
    }
  }, [pathname]);

  return (
    <div className="app-frame">
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>
      <aside className="sidebar" aria-label="Application navigation">
        <Link className="brand" to="/" aria-label="Omnius service overview">
          <svg
            className="brand-mark"
            viewBox="0 0 24 24"
            aria-hidden="true"
            focusable="false"
          >
            <path
              fill="currentColor"
              d="M4 5.25 12 1l8 4.25v9.5L12 19l-8-4.25v-9.5Zm2 1.2v7.1l6 3.2 6-3.2v-7.1l-6-3.2-6 3.2Zm5 2.05h2v7h-2v-7Z"
            />
          </svg>
          <span>Omnius</span>
        </Link>
        <nav className="primary-nav" aria-label="Primary">
          <ul>
            <li>
              <Link
                className="nav-link"
                to="/"
                activeOptions={{ exact: true }}
                activeProps={{ "aria-current": "page" }}
              >
                Service status
              </Link>
            </li>
            <li>
              <Link
                className="nav-link"
                to="/records"
                search={{ limit: 25 }}
                activeProps={{ "aria-current": "page" }}
              >
                Reference records
              </Link>
            </li>
            <OptionalAccountNavigation />
          </ul>
        </nav>
        <footer className="sidebar-meta">
          <div>Web build {BUILD_METADATA.revision}</div>
          <div>
            Contract <code className="build-hash">{BUILD_METADATA.contractHash}</code>
          </div>
        </footer>
      </aside>
      <div className="content-column">
        {mismatch === null ? null : (
          <section className="contract-banner" role="alert" aria-label="Contract mismatch">
            <strong>Contract mismatch.</strong> This web build targets{" "}
            <code>{mismatch.generatedAgainst}</code>, but the service reports{" "}
            <code>{mismatch.runtimeContractHash}</code>.
          </section>
        )}
        <main className="main-content" id="main-content" ref={mainContent} tabIndex={-1}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}
