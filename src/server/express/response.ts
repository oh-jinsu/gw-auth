import type { Response as ExpressResponse } from "express";

type HeadersWithSetCookie = Headers & {
  getSetCookie?: () => string[];
};

export async function writeWebResponse(
  source: Response,
  target: ExpressResponse,
): Promise<void> {
  target.status(source.status);
  copyHeaders(source.headers, target);

  if (source.body === null) {
    target.end();

    return;
  }

  target.send(Buffer.from(await source.arrayBuffer()));
}

function copyHeaders(headers: Headers, target: ExpressResponse): void {
  headers.forEach((value, name) => {
    if (name !== "set-cookie") {
      target.setHeader(name, value);
    }
  });

  const cookies = setCookies(headers);

  if (cookies.length > 0) {
    target.setHeader("set-cookie", cookies);
  }
}

function setCookies(headers: Headers): string[] {
  const values = (headers as HeadersWithSetCookie).getSetCookie?.();

  if (values && values.length > 0) {
    return values;
  }

  const value = headers.get("set-cookie");

  return value ? [value] : [];
}
