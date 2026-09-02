import type { AuthResult, BrowserOperation } from "gw-auth/core";

/** Core result shapes accepted by Next.js Route Handler and Server Action adapters. */
export type NextAuthOperationResult<TValue> =
  | AuthResult<TValue>
  | BrowserOperation<TValue>;

/** Adds an empty cookie-effect list to transport-independent authentication results. */
export function normalizeAuthOperation<TValue>(
  operation: NextAuthOperationResult<TValue>,
): BrowserOperation<TValue> {
  return isBrowserOperation(operation)
    ? operation
    : { result: operation, cookies: [] };
}

/** Recognizes the structured cookie effects returned by browser core operations. */
function isBrowserOperation<TValue>(
  operation: NextAuthOperationResult<TValue>,
): operation is BrowserOperation<TValue> {
  return "result" in operation && "cookies" in operation;
}
