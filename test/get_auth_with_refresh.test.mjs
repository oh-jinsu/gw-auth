import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { rm } from "node:fs/promises";
import { createServer } from "node:net";
import { fileURLToPath } from "node:url";
import { after, before, test } from "node:test";

import { resultFrom } from "gw-result";

const fixtureRoot = fileURLToPath(new URL("./fixtures/nextjs", import.meta.url));
const nextBin = fileURLToPath(new URL("../node_modules/next/dist/bin/next", import.meta.url));

let origin;
let nextServer;
let serverOutput = "";

before(async () => {
  const port = await availablePort();
  origin = `http://127.0.0.1:${port}`;
  nextServer = spawn(process.execPath, [nextBin, "dev", "--webpack", "--port", String(port)], {
    cwd: fixtureRoot,
    stdio: ["ignore", "pipe", "pipe"],
  });
  captureOutput(nextServer.stdout);
  captureOutput(nextServer.stderr);

  await waitForServer();
}, { timeout: 30_000 });

after(async () => {
  if (nextServer?.exitCode === null) {
    nextServer.kill("SIGTERM");
    await once(nextServer, "exit");
  }

  await rm(`${fixtureRoot}/.next`, { recursive: true, force: true });
});

test("returns verified auth without replacing cookies", async () => {
  const response = await fetch(`${origin}/api/auth`, {
    headers: { cookie: "service_access=valid-access" },
  });

  assert.equal(response.status, 200, serverOutput);
  assert.equal(response.headers.has("Set-Cookie"), false);
  assert.deepEqual(await response.json(), {
    ok: true,
    value: { userId: "user-1", sessionId: "session-1", role: "admin" },
  });
});

test("refreshes invalid access and applies replacement cookies", async () => {
  const response = await fetch(`${origin}/api/auth`, {
    headers: { cookie: "service_access=expired-access; service_refresh=valid-refresh" },
  });
  const setCookies = response.headers.getSetCookie().join("\n");

  assert.equal(response.status, 200, serverOutput);
  assert.match(setCookies, /service_access=replacement-access/);
  assert.match(setCookies, /service_refresh=replacement-refresh/);
  assert.deepEqual(await response.json(), {
    ok: true,
    value: { userId: "user-1", sessionId: "session-1", role: "admin" },
  });
});

test("applies terminal refresh cleanup cookies", async () => {
  const response = await fetch(`${origin}/api/auth`, {
    headers: { cookie: "service_refresh=invalid-refresh" },
  });
  const setCookies = response.headers.getSetCookie().join("\n");

  assert.equal(response.status, 401, serverOutput);
  assert.match(setCookies, /service_access=;/);
  assert.match(setCookies, /service_refresh=;/);
  assert.deepEqual(await response.json(), {
    ok: false,
    error: { code: "INVALID_REFRESH_TOKEN" },
  });
});

test("applies replacement cookies from a Server Action", async () => {
  const page = await fetch(`${origin}/action`);
  const html = await page.text();
  const actionName = html.match(/name="(\$ACTION_ID_[^"]+)"/)?.[1];
  assert(actionName, serverOutput);

  const form = new FormData();
  form.set(actionName, "");
  const response = await fetch(`${origin}/action`, {
    method: "POST",
    headers: {
      cookie: "service_access=expired-access; service_refresh=valid-refresh",
      origin,
    },
    body: form,
  });
  const setCookies = response.headers.getSetCookie().join("\n");

  assert.equal(response.status, 200, serverOutput);
  assert.match(setCookies, /service_access=replacement-access/);
  assert.match(setCookies, /service_refresh=replacement-refresh/);
});

/** Reserves an available localhost port for the fixture server. */
async function availablePort() {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert(address && typeof address === "object");
  server.close();
  await once(server, "close");

  return address.port;
}

/** Captures fixture output for assertion diagnostics. */
function captureOutput(stream) {
  stream.setEncoding("utf8");
  stream.on("data", (chunk) => {
    serverOutput += chunk;
  });
}

/** Waits until the fixture route is ready or reports its process output. */
async function waitForServer() {
  const deadline = Date.now() + 20_000;

  while (Date.now() < deadline && nextServer.exitCode === null) {
    const response = await resultFrom(() => fetch(`${origin}/api/auth`));

    if (response.isOk) {
      return;
    }

    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  assert.fail(`Next.js test server did not start.\n${serverOutput}`);
}
