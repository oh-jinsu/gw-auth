import { createAuthResolver } from "../../../../../../dist/nextjs/server/index.mjs";
import { sessionAuth } from "../../session";

const authResolver = createAuthResolver(sessionAuth);

/** Exercises each bound authentication lookup from one Route Handler. */
export async function GET(request) {
  const source = request.nextUrl.searchParams.get("source");
  const result = await resolveAuth(source);

  return result.isOk
    ? Response.json({ ok: true, value: result.value })
    : Response.json({ ok: false, error: { code: result.error.code } }, { status: 401 });
}

/** Selects the resolver method requested by an integration test. */
function resolveAuth(source) {
  if (source === "cookies") {
    return authResolver.cookies({ refresh: false });
  }

  return source === "cookies-refresh"
    ? authResolver.cookies()
    : authResolver.request();
}
