import { resultFrom } from "gw-result";

const validationOrigin = "https://gw-auth.invalid";

/** Returns a same-origin path or `undefined` when a redirect value is unsafe. */
export function sameOriginPath(value: string) {
  if (!value.startsWith("/") || value.startsWith("//") || value.includes("\\")) {
    return undefined;
  }

  const resolved = resultFrom(() => new URL(value, validationOrigin));

  return resolved.isOk && resolved.value.origin === validationOrigin ? value : undefined;
}
