const PUBLIC_BASE_SEGMENT = /^[A-Za-z0-9._~-]+$/u;

/**
 * Validates and canonicalizes the public path at which the web application and
 * its same-origin service transports are mounted.
 */
export function normalizePublicBasePath(value: string | undefined = "/"): string {
  if (
    value.length === 0 ||
    value.trim() !== value ||
    !value.startsWith("/") ||
    value.startsWith("//") ||
    value.includes("//") ||
    /[?#%\\]/u.test(value)
  ) {
    throw new TypeError("Public base path must be a canonical absolute path.");
  }

  const canonical = value.endsWith("/") && value.length > 1 ? value.slice(0, -1) : value;
  if (canonical === "/") {
    return canonical;
  }

  const invalidSegment = canonical
    .slice(1)
    .split("/")
    .some(
      (segment) =>
        segment.length === 0 ||
        segment === "." ||
        segment === ".." ||
        !PUBLIC_BASE_SEGMENT.test(segment),
    );
  if (invalidSegment) {
    throw new TypeError("Public base path must be a canonical absolute path.");
  }

  return canonical;
}
