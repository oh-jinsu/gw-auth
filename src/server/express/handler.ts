import type {
  NextFunction,
  Request as ExpressRequest,
  RequestHandler,
  Response as ExpressResponse,
} from "express";
import { resultFrom } from "gw-result";

import { webRequestFromExpress } from "./request";
import { writeWebResponse } from "./response";

export type WebHandler = (request: Request) => Response | Promise<Response>;

export function expressHandler(handler: WebHandler): RequestHandler {
  return (request, response, next) => {
    void handleRequest(handler, request, response, next);
  };
}

async function handleRequest(
  handler: WebHandler,
  request: ExpressRequest,
  response: ExpressResponse,
  next: NextFunction,
): Promise<void> {
  const handled = await resultFrom(async () => {
    return await handler(webRequestFromExpress(request));
  });

  if (handled.isErr) {
    next(handled.error);

    return;
  }

  const written = await resultFrom(() => writeWebResponse(handled.value, response));

  if (written.isErr) {
    next(written.error);
  }
}
