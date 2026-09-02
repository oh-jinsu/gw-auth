/** Returns a same-origin path or `undefined` when a redirect value is unsafe. */
export function sameOriginPath(value: string) {
  if (!value.startsWith("/") || value.startsWith("//")) {
    return undefined;
  }

  return value;
}
