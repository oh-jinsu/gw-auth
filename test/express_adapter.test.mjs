import assert from "node:assert/strict";
import test from "node:test";
import express from "express";

import {
  expressHandler,
  webRequestFromExpress,
  writeWebResponse,
} from "../dist/server/express/index.mjs";

test("converts an Express JSON request to a Web request", async () => {
  const converted = webRequestFromExpress(expressRequest());

  assert.equal(converted.url, "https://example.test/v1/auth/login?source=app");
  assert.equal(converted.method, "POST");
  assert.deepEqual(await converted.json(), { code: "credential" });
});

test("writes status, body, and multiple cookies to Express", async () => {
  const headers = new Headers({ "content-type": "application/json" });
  headers.append("set-cookie", "access=one; HttpOnly");
  headers.append("set-cookie", "refresh=two; HttpOnly");
  const source = new Response(JSON.stringify({ ok: true }), {
    status: 201,
    headers,
  });
  const target = expressResponse();

  await writeWebResponse(source, target);

  assert.equal(target.statusCode, 201);
  assert.deepEqual(target.headers.get("set-cookie"), [
    "access=one; HttpOnly",
    "refresh=two; HttpOnly",
  ]);
  assert.deepEqual(JSON.parse(target.body.toString()), { ok: true });
});

test("passes handler failures to Express error middleware", async () => {
  const failure = new Error("failed");

  await new Promise((resolve, reject) => {
    expressHandler(() => {
      throw failure;
    })(expressRequest(), expressResponse(), (error) => {
      try {
        assert.equal(error, failure);
        resolve();
      } catch (assertionError) {
        reject(assertionError);
      }
    });
  });
});

test("runs a Web handler in a real Express app", async (context) => {
  const app = express();
  app.use(express.json());
  app.post("/auth", expressHandler(async (request) => {
    return Response.json(await request.json(), { status: 201 });
  }));
  const server = await listen(app);
  context.after(() => new Promise((resolve) => server.close(resolve)));
  const address = server.address();

  assert.notEqual(address, null);

  const response = await fetch(`http://127.0.0.1:${address.port}/auth`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ provider: "apple" }),
  });

  assert.equal(response.status, 201);
  assert.deepEqual(await response.json(), { provider: "apple" });
});

function listen(app) {
  return new Promise((resolve) => {
    const server = app.listen(0, "127.0.0.1", () => resolve(server));
  });
}

function expressRequest() {
  return {
    method: "POST",
    protocol: "https",
    originalUrl: "/v1/auth/login?source=app",
    url: "/v1/auth/login?source=app",
    headers: {
      "content-type": "application/json",
      host: "example.test",
    },
    body: { code: "credential" },
    get(name) {
      return this.headers[name.toLowerCase()];
    },
  };
}

function expressResponse() {
  return {
    statusCode: 200,
    headers: new Map(),
    body: Buffer.alloc(0),
    status(value) {
      this.statusCode = value;

      return this;
    },
    setHeader(name, value) {
      this.headers.set(name.toLowerCase(), value);

      return this;
    },
    send(value) {
      this.body = Buffer.from(value);

      return this;
    },
    end() {
      return this;
    },
  };
}
