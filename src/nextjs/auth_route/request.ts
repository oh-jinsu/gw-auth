import { resultFrom } from "gw-result";
import type { NextRequest } from "next/server.js";

/** Reads a JSON object without allowing parser failures to escape the adapter. */
export async function readJsonObject(request: NextRequest) {
  if (!hasJsonContentType(request)) {
    return undefined;
  }

  const parsed = await resultFrom(() => request.json() as Promise<unknown>);

  return parsed.isOk && isRecord(parsed.value) ? parsed.value : undefined;
}

/** Accepts JSON and structured-syntax JSON media types only. */
function hasJsonContentType(request: NextRequest) {
  const contentType = request.headers.get("Content-Type")?.split(";", 1)[0].trim().toLowerCase();

  return contentType === "application/json"
    || (contentType?.startsWith("application/") && contentType.endsWith("+json"));
}

/** Reads a required non-empty string property from an untrusted request object. */
export function requiredString(body: Record<string, unknown>, key: string) {
  const value = body[key];

  return typeof value === "string" && value !== "" ? value : undefined;
}

/** Reads an optional string while rejecting present values of another type. */
export function optionalString(body: Record<string, unknown>, key: string) {
  const value = body[key];

  return value === undefined || typeof value === "string" ? value : null;
}

/** Reads Google, Kakao, Naver, or Apple callback fields from query or form data. */
export async function readOAuthCallback(request: NextRequest) {
  const values = request.method === "POST"
    ? await callbackForm(request)
    : request.nextUrl.searchParams;

  return {
    code: callbackString(values?.get("code")),
    state: callbackString(values?.get("state")),
  };
}

/** Converts text form fields to framework-neutral values while omitting uploaded files. */
export async function readFormStrings(request: NextRequest) {
  const values = await callbackForm(request);

  if (!values) {
    return undefined;
  }

  return Object.fromEntries(
    [...values].filter((entry): entry is [string, string] => typeof entry[1] === "string"),
  );
}

/** Accepts only text callback fields and rejects uploaded files. */
function callbackString(value: FormDataEntryValue | string | null | undefined) {
  return typeof value === "string" ? value : "";
}

/** Parses an OAuth form-post callback without throwing on malformed data. */
async function callbackForm(request: NextRequest) {
  const parsed = await resultFrom(() => request.formData());

  return parsed.isOk ? parsed.value : undefined;
}

/** Narrows unknown JSON input to an object with named fields. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
