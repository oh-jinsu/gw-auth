/** Reads exactly one RFC bearer credential without accepting surrounding whitespace. */
export function bearerToken(authorization: string | null | undefined) {
  const matched = authorization?.match(/^Bearer ([^\s]+)$/i);

  return matched?.[1];
}
