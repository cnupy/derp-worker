// Example admission controller for derp-worker.
//
// It speaks derper's admission protocol (tailcfg.DERPAdmitClientRequest and
// DERPAdmitClientResponse): the relay POSTs
// {"NodePublic":"nodekey:<64 hex>","Source":"<client ip>"} and this Worker
// answers 200 {"Allow":true|false}.
//
// The allowlist is the ALLOWED_KEYS secret: "nodekey:<64 hex>" keys
// separated by commas or spaces. Changing it redeploys only this Worker;
// clients already connected to the relay stay connected.
//
// Bind it to the relay as a service binding so it needs no public route.

interface Env {
  ALLOWED_KEYS?: string;
}

const KEY_RE = /^nodekey:[0-9a-f]{64}$/;

function allowlist(s: string | undefined): Set<string> {
  const set = new Set<string>();
  for (const part of (s ?? "").split(/[,\s]+/)) {
    const k = part.trim().toLowerCase();
    if (KEY_RE.test(k)) set.add(k);
  }
  return set;
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    if (req.method !== "POST") {
      return new Response("POST only\n", { status: 405, headers: { Allow: "POST" } });
    }
    let body: unknown;
    try {
      body = JSON.parse((await req.text()).slice(0, 4096));
    } catch {
      return new Response("bad JSON\n", { status: 400 });
    }
    const nodePublic = (body as { NodePublic?: unknown } | null)?.NodePublic;
    if (typeof nodePublic !== "string" || !KEY_RE.test(nodePublic.toLowerCase())) {
      return new Response("missing or bad NodePublic\n", { status: 400 });
    }
    const allow = allowlist(env.ALLOWED_KEYS).has(nodePublic.toLowerCase());
    console.log(`admission ${allow ? "allow" : "deny"} ${nodePublic}`);
    return Response.json({ Allow: allow });
  },
};
