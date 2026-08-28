import type { Request as ExpressRequest } from "express";

export function webRequestFromExpress(request: ExpressRequest): Request {
  const body = bodyFromExpress(request);
  const init: RequestInit = {
    method: request.method,
    headers: headersFromExpress(request),
    ...(body === undefined ? {} : { body }),
  };

  return new Request(urlFromExpress(request), init);
}

function urlFromExpress(request: ExpressRequest): string {
  const host = request.get("host") ?? "localhost";
  const path = request.originalUrl || request.url;

  return new URL(path, `${request.protocol}://${host}`).toString();
}

function headersFromExpress(request: ExpressRequest): Headers {
  const headers = new Headers();

  for (const [name, value] of Object.entries(request.headers)) {
    appendHeader(headers, name, value);
  }

  return headers;
}

function appendHeader(
  headers: Headers,
  name: string,
  value: string | string[] | undefined,
): void {
  if (Array.isArray(value)) {
    value.forEach((item) => headers.append(name, item));
  } else if (value !== undefined) {
    headers.set(name, value);
  }
}

function bodyFromExpress(request: ExpressRequest): BodyInit | undefined {
  if (request.method === "GET" || request.method === "HEAD") {
    return undefined;
  }

  const body: unknown = request.body;

  if (body === undefined || body === null || typeof body === "string") {
    return body ?? undefined;
  }

  if (body instanceof Uint8Array) {
    return Uint8Array.from(body).buffer;
  }

  return serializedBody(body, request.get("content-type"));
}

function serializedBody(body: unknown, contentType?: string): string {
  if (contentType?.includes("application/x-www-form-urlencoded")) {
    return urlEncodedBody(body);
  }

  return JSON.stringify(body);
}

function urlEncodedBody(body: unknown): string {
  if (typeof body !== "object" || body === null) {
    return String(body);
  }

  const entries = Object.entries(body).map(([key, value]) => [key, String(value)]);

  return new URLSearchParams(entries).toString();
}
