import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFile, readdir } from "node:fs/promises";
import test from "node:test";

import * as esmCore from "../dist/core/index.mjs";
import * as esmNext from "../dist/nextjs/server/index.mjs";
import * as esmClient from "../dist/nextjs/client/index.mjs";

const require = createRequire(import.meta.url);

test("loads the documented ESM and CommonJS entry points", () => {
  const cjsCore = require("../dist/core/index.js");
  const cjsNext = require("../dist/nextjs/server/index.js");
  const cjsClient = require("../dist/nextjs/client/index.js");

  assert.deepEqual(Object.keys(esmCore).sort(), ["AuthError", "createAuth", "isAuthError"]);
  assert.deepEqual(Object.keys(cjsCore).sort(), ["AuthError", "createAuth", "isAuthError"]);
  assert.deepEqual(Object.keys(esmNext).sort(), [
    "getAuth",
    "nextRequestCookies",
    "routeHandler",
    "serverAction",
    "withAuth",
  ]);
  assert.deepEqual(Object.keys(cjsNext).sort(), [
    "getAuth",
    "nextRequestCookies",
    "routeHandler",
    "serverAction",
    "withAuth",
  ]);
  assert.deepEqual(Object.keys(esmClient).sort(), [
    "AuthProvider",
    "authRequest",
    "startOAuth",
    "useAuth",
  ]);
  assert.deepEqual(Object.keys(cjsClient).sort(), [
    "AuthProvider",
    "authRequest",
    "startOAuth",
    "useAuth",
  ]);
});

test("publishes only the core and explicit Next.js entry points", async () => {
  const files = await distributionFiles(new URL("../dist/", import.meta.url));

  assert.deepEqual(files, [
    "core/index.d.mts",
    "core/index.d.ts",
    "core/index.js",
    "core/index.mjs",
    "nextjs/client/index.d.mts",
    "nextjs/client/index.d.ts",
    "nextjs/client/index.js",
    "nextjs/client/index.mjs",
    "nextjs/server/index.d.mts",
    "nextjs/server/index.d.ts",
    "nextjs/server/index.js",
    "nextjs/server/index.mjs",
  ]);
});

test("preserves the Next.js client-module directive", async () => {
  const source = await readFile(
    new URL("../dist/nextjs/client/index.mjs", import.meta.url),
    "utf8",
  );

  assert.match(source, /^"use client";/);
  assert.doesNotMatch(source, /gw-auth\/core/);
});

/** Recursively returns stable relative paths for packaged build assertions. */
async function distributionFiles(root, path = "") {
  const entries = await readdir(new URL(path, root), { withFileTypes: true });
  const files = await Promise.all(entries.map(async (entry) => {
    const relative = `${path}${entry.name}`;

    return entry.isDirectory()
      ? distributionFiles(root, `${relative}/`)
      : [relative];
  }));

  return files.flat().sort();
}
