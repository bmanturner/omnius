import { spawn } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const webDirectory = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const workspaceRoot = resolve(webDirectory, "..");
const fixturePort = Number.parseInt(process.env.OMNIUS_E2E_PORT ?? "4174", 10);
const binaryValue = process.env.OMNIUS_E2E_PROFILE_BIN;
if (binaryValue === undefined || binaryValue.length === 0) {
  throw new Error("OMNIUS_E2E_PROFILE_BIN must name the generated profile binary");
}
const binary = resolve(workspaceRoot, binaryValue);
let stopping = false;
const service = spawn(binary, ["server"], {
  cwd: workspaceRoot,
  env: {
    ...process.env,
    OMNIUS__SERVER__LISTEN_ADDRESS: `127.0.0.1:${fixturePort}`,
  },
  stdio: ["ignore", "pipe", "pipe"],
});
for (const stream of [service.stdout, service.stderr]) {
  stream?.setEncoding("utf8");
  stream?.on("data", (chunk) => process.stderr.write(chunk));
}

async function shutdown() {
  if (stopping) return;
  stopping = true;
  if (service.exitCode === null) {
    service.kill("SIGTERM");
    await Promise.race([
      new Promise((resolveExit) => service.once("exit", resolveExit)),
      new Promise((resolveDelay) => setTimeout(resolveDelay, 5_000)).then(() => service.kill("SIGKILL")),
    ]);
  }
}

for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => void shutdown().finally(() => process.exit(0)));
}
service.once("error", (error) => {
  process.stderr.write(`generated profile fixture failed: ${error.message}\n`);
  process.exit(1);
});
service.once("exit", (code, signal) => {
  if (!stopping) {
    process.stderr.write(`generated profile fixture exited unexpectedly (code=${String(code)}, signal=${String(signal)})\n`);
    process.exit(code ?? 1);
  }
});
await new Promise(() => {});
