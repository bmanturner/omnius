import { useContractMismatch } from "@omnius/web-sdk/react";
import { Link, Outlet, useRouterState } from "@tanstack/react-router";
import { useEffect, useRef } from "react";

import { BUILD_METADATA } from "../build-metadata";

export function AppShell() {
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const mismatch = useContractMismatch();
  const mainContent = useRef<HTMLElement>(null);
  const previousPathname = useRef(pathname);

  useEffect(() => {
    document.title = pathname === "/" ? "Service overview · Omnius" : "Page not found · Omnius";
    if (pathname !== previousPathname.current) {
      previousPathname.current = pathname;
      mainContent.current?.focus();
    }
  }, [pathname]);

  return (
    <div className="app-frame">
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <aside className="sidebar" aria-label="Application navigation">
        <Link className="brand" to="/" aria-label="Omnius service overview">Omnius</Link>
        <nav className="primary-nav" aria-label="Primary">
          <ul>
            <li>
              <Link className="nav-link" to="/" activeOptions={{ exact: true }} activeProps={{ "aria-current": "page" }}>
                Service status
              </Link>
            </li>
          </ul>
        </nav>
        <footer className="sidebar-meta">
          <div>Web build {BUILD_METADATA.revision}</div>
          <div>Contract <code className="build-hash">{BUILD_METADATA.contractHash}</code></div>
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
