import { useContractMismatch } from "@omnius/web-sdk/react";
import { Link, Outlet, useRouterState } from "@tanstack/react-router";
import { useEffect, useRef } from "react";

const TITLE_BY_PATH: Readonly<Record<string, string>> = {
  "/": "Reading list",
  "/login": "Sign in",
  "/register": "Create account",
  "/verify-email": "Verify email",
  "/forgot-password": "Forgot password",
  "/reset-password": "Reset password",
};

export function AppShell() {
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const mismatch = useContractMismatch();
  const mainContent = useRef<HTMLElement>(null);
  const previousPathname = useRef(pathname);

  useEffect(() => {
    document.title = `${TITLE_BY_PATH[pathname] ?? "Page not found"} · Reading List`;
    if (pathname !== previousPathname.current) {
      previousPathname.current = pathname;
      mainContent.current?.focus();
    }
  }, [pathname]);

  return (
    <div className="app-frame">
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <header className="site-header">
        <Link className="brand" to="/" aria-label="Reading List home">
          <span className="brand-mark" aria-hidden="true">R</span>
          <span>Reading List</span>
        </Link>
        <nav aria-label="Account">
          <Link to="/login">Sign in</Link>
          <Link to="/register">Register</Link>
        </nav>
      </header>
      {mismatch === null ? null : (
        <section className="contract-banner" role="alert" aria-label="Contract mismatch">
          <strong>This browser build is out of date.</strong> Refresh after the service is updated.
        </section>
      )}
      <main className="main-content" id="main-content" ref={mainContent} tabIndex={-1}>
        <Outlet />
      </main>
      <footer className="site-footer">A private place for what you want to read next.</footer>
    </div>
  );
}
