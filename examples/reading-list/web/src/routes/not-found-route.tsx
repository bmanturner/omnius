import { Link } from "@tanstack/react-router";

export function NotFoundRoute() {
  return (
    <section className="auth-card" aria-labelledby="not-found-title">
      <p className="eyebrow">404</p>
      <h1 id="not-found-title">Page not found</h1>
      <p>The page you requested is not part of Reading List.</p>
      <Link className="button secondary" to="/">Return to your list</Link>
    </section>
  );
}
