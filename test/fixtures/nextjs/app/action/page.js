import { getAuthWithRefresh } from "../../../../../dist/nextjs/server/index.mjs";

import { session } from "../session";

export default function ActionPage() {
  return (
    <form action={refreshSession}>
      <button type="submit">Refresh session</button>
    </form>
  );
}

/** Refreshes the request session before protected Server Action work. */
async function refreshSession() {
  "use server";

  await getAuthWithRefresh(session);
}
