import { Link } from "@tanstack/react-router";

export function NotFoundRoute() {
  return (
    <section className="not-found">
      <p className="eyebrow">404</p>
      <h1>Page not found</h1>
      <p className="page-intro">
        This dashboard route does not exist. Use the primary navigation or return to the service
        overview.
      </p>
      <p>
        <Link className="button-link" to="/">
          Return to service overview
        </Link>
      </p>
    </section>
  );
}
