import { getAuthWithRefresh } from "../../../../../../dist/nextjs/server/index.mjs";
import { session } from "../../session";

export async function GET() {
  const result = await getAuthWithRefresh(session);

  return result.isOk
    ? Response.json({ ok: true, value: result.value })
    : Response.json({ ok: false, error: { code: result.error.code } }, { status: 401 });
}
