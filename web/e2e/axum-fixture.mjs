import { createPublicKey, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const webDirectory = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const workspaceRoot = resolve(webDirectory, "..");
const fixturePort = Number.parseInt(process.env.OMNIUS_E2E_PORT ?? "4174", 10);
const apiPort = fixturePort;
const vitePort = fixturePort + 1;
const cursorSigningKey = "0123456789abcdef0123456789abcdef";
const jwtIssuer = "https://issuer.example.test";
const fixtureDirectory = mkdtempSync(join(tmpdir(), "omnius-web-e2e-"));
const jwtPrivateKeyPath = join(workspaceRoot, "crates/auth-jwt/tests/test_rsa_key.pem");
const oauthSigningPrivateKey = readFileSync(jwtPrivateKeyPath, "utf8");
const oauthSigningPublicJwk = createPublicKey(oauthSigningPrivateKey).export({ format: "jwk" });
const oauthTokenPepper = Buffer.alloc(32, 7).toString("base64url");
const registrationInvitationPepper = Buffer.alloc(32, 11).toString("base64url");
const apiKeyPepper = Buffer.alloc(32, 13).toString("base64url");
const apiBinary = resolve(
  workspaceRoot,
  process.env.OMNIUS_E2E_API_BIN ?? "target/debug/omnius-api-server",
);
const provisionBinary = resolve(
  workspaceRoot,
  process.env.OMNIUS_E2E_PROVISION_BIN ?? "target/debug/examples/e2e_provision",
);
const distIndex = join(webDirectory, "dist/index.html");

let postgresContainer;
let apiProcess;
let viteProcess;
let jwksServer;
let stopping = false;
let databaseUrl = process.env.OMNIUS_E2E_POSTGRES_URL;
const passwordPepper = "playwright-password-pepper";
const loginIdentifier = "person@example.test";
const loginPassword = "correct horse battery staple";

function sanitized(value) {
  let output = String(value);
  for (const secret of [
    databaseUrl,
    cursorSigningKey,
    passwordPepper,
    loginPassword,
    oauthTokenPepper,
    registrationInvitationPepper,
    apiKeyPepper,
    oauthSigningPrivateKey,
  ]) {
    if (typeof secret === "string" && secret.length > 0) {
      output = output.replaceAll(secret, "[REDACTED]");
    }
  }
  return output;
}

function commandResult(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: workspaceRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    ...options,
  });
  if (result.error !== undefined || result.status !== 0) {
    const detail = sanitized(result.stderr || result.stdout || result.error?.message || "no output");
    throw new Error(`${command} failed: ${detail.trim()}`);
  }
  return result.stdout.trim();
}

function delay(milliseconds) {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));
}

function createFixtureBaseConfig() {
  if (databaseUrl === undefined) {
    throw new Error("PostgreSQL fixture URL is unavailable");
  }
  const source = readFileSync(join(workspaceRoot, "config/reference.toml"), "utf8");
  const emailProvider = `[email.provider]\n\
# Capturing is accepted only when --environment test is explicitly selected.\n\
provider = "smtp"\n\
relay = "\${SMTP_RELAY}"\n\
port = 465\n\
tls = "implicit"\n\
username = "\${SMTP_USERNAME}"\n\
password = "\${SMTP_PASSWORD}"\n`;
  let materialized = source.replace(
    emailProvider,
    `[email.provider]\nprovider = "capturing"\ncapacity = 16\n`,
  );
  if (materialized === source) {
    throw new Error("Reference email provider block changed; update the E2E fixture override");
  }
  for (const [placeholder, value] of [
    ["${POSTGRES_URL}", databaseUrl],
    ["${CURSOR_SIGNING_KEY}", cursorSigningKey],
    ["${PASSWORD_PEPPER}", passwordPepper],
    ["${PUBLIC_APP_URL}", `http://127.0.0.1:${fixturePort}`],
    ["${REGISTRATION_INVITATION_PEPPER}", registrationInvitationPepper],
    ["${API_KEY_PEPPER}", apiKeyPepper],
    ["${OAUTH_ISSUER}", `http://127.0.0.1:${fixturePort}`],
    ["${OAUTH_TOKEN_PEPPER}", oauthTokenPepper],
    ["${OAUTH_SIGNING_JWK_N}", oauthSigningPublicJwk.n],
    ["${OAUTH_SIGNING_PRIVATE_KEY_PKCS8_PEM}", oauthSigningPrivateKey],
    ["${EMAIL_TEMPLATE_DIR}", join(workspaceRoot, "apps/api-server/email-templates")],
  ]) {
    if (!materialized.includes(placeholder)) {
      throw new Error(`Reference placeholder ${placeholder} changed; update the E2E fixture`);
    }
    materialized = materialized.replaceAll(placeholder, value);
  }
  const unresolved = /\$\{[A-Z0-9_]+\}/u.exec(materialized);
  if (unresolved !== null) {
    throw new Error(`Unresolved reference placeholder ${unresolved[0]}`);
  }
  const path = join(fixtureDirectory, "base.toml");
  writeFileSync(path, materialized, { mode: 0o600 });
  return path;
}

function publishedLoopbackPort(container, port) {
  const published = commandResult("docker", ["port", container, `${String(port)}/tcp`]);
  const match = /127\.0\.0\.1:(\d+)$/u.exec(published);
  if (match?.[1] === undefined) {
    throw new Error(`Docker did not publish port ${String(port)} on loopback IPv4`);
  }
  return Number.parseInt(match[1], 10);
}

async function provisionPostgres() {
  if (databaseUrl !== undefined) {
    return;
  }
  const suffix = randomUUID().replaceAll("-", "");
  const database = `omnius_e2e_${suffix}`;
  const username = `omnius_e2e_${suffix}`;
  const password = `omnius-pg-${suffix}-password`;
  const containerName = `omnius-web-e2e-${suffix}`;
  postgresContainer = commandResult("docker", [
    "run",
    "--rm",
    "--detach",
    "--name",
    containerName,
    "--publish",
    "127.0.0.1::5432",
    "--env",
    `POSTGRES_DB=${database}`,
    "--env",
    `POSTGRES_USER=${username}`,
    "--env",
    `POSTGRES_PASSWORD=${password}`,
    "--env",
    "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256",
    "--health-cmd",
    `pg_isready -U ${username} -d ${database}`,
    "--health-interval",
    "1s",
    "--health-timeout",
    "5s",
    "--health-retries",
    "60",
    "postgres@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94",
  ]);

  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    const health = commandResult("docker", [
      "inspect",
      "--format",
      "{{.State.Health.Status}}",
      postgresContainer,
    ]);
    if (health === "healthy") {
      break;
    }
    if (health === "unhealthy") {
      throw new Error("PostgreSQL E2E container became unhealthy");
    }
    await delay(250);
  }
  if (Date.now() >= deadline) {
    throw new Error("PostgreSQL E2E container did not become healthy before its deadline");
  }

  const postgresPort = publishedLoopbackPort(postgresContainer, 5432);
  databaseUrl = `postgres://${encodeURIComponent(username)}:${encodeURIComponent(password)}@127.0.0.1:${String(postgresPort)}/${encodeURIComponent(database)}`;
}

async function startJwksServer() {
  const privateKey = readFileSync(jwtPrivateKeyPath, "utf8");
  const publicJwk = createPublicKey(privateKey).export({ format: "jwk" });
  const body = JSON.stringify({
    keys: [
      {
        ...publicJwk,
        alg: "RS256",
        key_ops: ["verify"],
        kid: "profile-key",
        use: "sig",
      },
    ],
  });
  jwksServer = createServer((request, response) => {
    if (request.method === "GET" && request.url === "/jwks") {
      response.writeHead(200, {
        "cache-control": "no-store",
        "content-type": "application/json",
      });
      response.end(body);
      return;
    }
    response.writeHead(404, { "content-type": "text/plain" });
    response.end("not found");
  });
  await new Promise((resolveListen, rejectListen) => {
    jwksServer.once("error", rejectListen);
    jwksServer.listen(0, "127.0.0.1", resolveListen);
  });
  const address = jwksServer.address();
  if (address === null || typeof address === "string") {
    throw new Error("JWKS fixture did not bind a TCP address");
  }
  return `http://127.0.0.1:${address.port}/jwks`;
}

function serverEnvironment() {
  if (databaseUrl === undefined) {
    throw new Error("PostgreSQL fixture URL is unavailable");
  }
  return {
    ...process.env,
    POSTGRES_URL: databaseUrl,
    DATABASE_URL: databaseUrl,
    CURSOR_SIGNING_KEY: cursorSigningKey,
    JWT_ISSUER: jwtIssuer,
    PASSWORD_PEPPER: passwordPepper,
    OMNIUS_E2E_LOGIN_IDENTIFIER: loginIdentifier,
    OMNIUS_E2E_LOGIN_PASSWORD: loginPassword,
    OMNIUS_E2E_PASSWORD_PEPPER: passwordPepper,
    OMNIUS__AUTH__PASSWORD__PEPPER__SECRET: passwordPepper,
    OMNIUS__AUTH__REGISTRATION__MODE: "self_service",
    PUBLIC_APP_URL: `http://127.0.0.1:${fixturePort}`,
    REGISTRATION_INVITATION_PEPPER: registrationInvitationPepper,
    API_KEY_PEPPER: apiKeyPepper,
    OAUTH_ISSUER: `http://127.0.0.1:${fixturePort}`,
    OAUTH_TOKEN_PEPPER: oauthTokenPepper,
    OAUTH_SIGNING_JWK_N: oauthSigningPublicJwk.n,
    OAUTH_SIGNING_PRIVATE_KEY_PKCS8_PEM: oauthSigningPrivateKey,
    EMAIL_TEMPLATE_DIR: join(workspaceRoot, "apps/api-server/email-templates"),
    OMNIUS__POSTGRES__URL: databaseUrl,
    OMNIUS__PAGINATION__CURSOR_SIGNING_KEY: cursorSigningKey,
    OMNIUS__POSTGRES__TLS_MODE: "disable",
    OMNIUS__POSTGRES__CONNECT_TIMEOUT: "2s",
    OMNIUS__POSTGRES__ACQUIRE_TIMEOUT: "1s",
    OMNIUS__POSTGRES__HEALTH_TIMEOUT: "1s",
    OMNIUS__STATIC_DELIVERY__ASSET_DIR: join(webDirectory, "dist"),
    OMNIUS__STATIC_DELIVERY__BASE_PATH: process.env.OMNIUS_WEB_BASE_PATH ?? "/",
    OMNIUS__STATIC_DELIVERY__SERVE_IN_NONPRODUCTION: "true",
    OMNIUS__HEALTH__REFRESH_INTERVAL: "100ms",
    OMNIUS__REALTIME__SSE_HEARTBEAT_INTERVAL: "1s",
    OMNIUS__HEALTH__STALE_AFTER: "2s",
    OMNIUS__HEALTH__SHUTDOWN_TIMEOUT: "500ms",
    OMNIUS__AUTH__SESSION__SECURE: "false",
    OMNIUS__AUTH__SESSION__COOKIE_NAME: "omnius_session",
    OMNIUS__TELEMETRY__ENVIRONMENT: "test",
    OMNIUS__TELEMETRY__FORMAT: "json",
  };
}

function runMigration(baseConfig, environmentConfig) {
  commandResult(
    apiBinary,
    [
      "migrate",
      "--config",
      baseConfig,
      "--environment",
      "test",
      "--environment-config",
      environmentConfig,
    ],
    { env: serverEnvironment() },
  );
}

function startApi(baseConfig, environmentConfig) {
  apiProcess = spawn(
    apiBinary,
    [
      "server",
      "--config",
      baseConfig,
      "--environment",
      "test",
      "--environment-config",
      environmentConfig,
      "--listen-address",
      `127.0.0.1:${apiPort}`,
    ],
    {
      cwd: workspaceRoot,
      env: serverEnvironment(),
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  for (const stream of [apiProcess.stdout, apiProcess.stderr]) {
    stream?.setEncoding("utf8");
    stream?.on("data", (chunk) => process.stderr.write(sanitized(chunk)));
  }
  apiProcess.once("error", (error) => {
    process.stderr.write(`Axum fixture failed to launch: ${sanitized(error.message)}\n`);
  });
  apiProcess.once("exit", (code, signal) => {
    if (!stopping) {
      process.stderr.write(`Axum fixture exited unexpectedly (code=${String(code)}, signal=${String(signal)})\n`);
      void shutdown().finally(() => process.exit(code ?? 1));
    }
  });
}

function provisionBrowserIdentity() {
  commandResult(provisionBinary, [], { env: serverEnvironment() });
}

function startVitePreview() {
  viteProcess = spawn(
    "pnpm",
    ["exec", "vite", "preview", "--host", "127.0.0.1", "--port", String(vitePort)],
    {
      cwd: webDirectory,
      env: {
        ...process.env,
        OMNIUS_DEV_PROXY_TARGET: `http://127.0.0.1:${apiPort}`,
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  for (const stream of [viteProcess.stdout, viteProcess.stderr]) {
    stream?.setEncoding("utf8");
    stream?.on("data", (chunk) => process.stderr.write(sanitized(chunk)));
  }
  viteProcess.once("exit", (code, signal) => {
    if (!stopping) {
      process.stderr.write(
        `Vite preview exited unexpectedly (code=${String(code)}, signal=${String(signal)})\n`,
      );
      void shutdown().finally(() => process.exit(code ?? 1));
    }
  });
}

async function shutdown() {
  if (stopping) {
    return;
  }
  stopping = true;
  if (viteProcess !== undefined && viteProcess.exitCode === null) {
    viteProcess.kill("SIGTERM");
    await Promise.race([
      new Promise((resolveExit) => viteProcess.once("exit", resolveExit)),
      delay(5_000).then(() => viteProcess?.kill("SIGKILL")),
    ]);
  }
  if (apiProcess !== undefined && apiProcess.exitCode === null) {
    apiProcess.kill("SIGTERM");
    await Promise.race([
      new Promise((resolveExit) => apiProcess.once("exit", resolveExit)),
      delay(5_000).then(() => apiProcess?.kill("SIGKILL")),
    ]);
  }
  if (jwksServer !== undefined) {
    await new Promise((resolveClose) => jwksServer.close(resolveClose));
  }
  if (postgresContainer !== undefined) {
    spawnSync("docker", ["rm", "--force", postgresContainer], {
      cwd: workspaceRoot,
      stdio: "ignore",
    });
  }
  rmSync(fixtureDirectory, { recursive: true, force: true });
}

async function main() {
  if (!existsSync(distIndex)) {
    throw new Error("web/dist is unavailable; run the production web build before Playwright");
  }
  if (!existsSync(apiBinary)) {
    throw new Error(
      `Axum binary is unavailable at ${apiBinary}; build omnius-api-server or set OMNIUS_E2E_API_BIN`,
    );
  }
  if (!existsSync(provisionBinary)) {
    throw new Error(
      `E2E provisioner is unavailable at ${provisionBinary}; build the api-server e2e_provision example or set OMNIUS_E2E_PROVISION_BIN`,
    );
  }
  await provisionPostgres();
  const baseConfig = createFixtureBaseConfig();
  const jwksUrl = await startJwksServer();
  const environmentConfig = join(fixtureDirectory, "jwt.toml");
  writeFileSync(
    environmentConfig,
    `[auth.jwt]\nissuers = [{ issuer = "${jwtIssuer}", jwks_url = "${jwksUrl}" }]\n\
[http]\ntrusted_origins = ["http://127.0.0.1:${fixturePort}", "http://127.0.0.1:${vitePort}"]\n\
[outbound_http.url_policy]\nallow_development_loopback_http = true\n`,
    { mode: 0o600 },
  );
  runMigration(baseConfig, environmentConfig);
  provisionBrowserIdentity();
  startApi(baseConfig, environmentConfig);
  startVitePreview();
}

for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.once(signal, () => {
    void shutdown().finally(() => process.exit(0));
  });
}
process.once("uncaughtException", (error) => {
  process.stderr.write(`${sanitized(error instanceof Error ? error.stack : error)}\n`);
  void shutdown().finally(() => process.exit(1));
});
process.once("unhandledRejection", (error) => {
  process.stderr.write(`${sanitized(error instanceof Error ? error.stack : error)}\n`);
  void shutdown().finally(() => process.exit(1));
});

await main();
