// Client admission for the relay.
//
// The relay asks an Authorize function whether a client key may connect.
// The default one speaks derper's admission controller protocol
// (derper --verify-client-url, tailcfg.DERPAdmitClientRequest/Response):
// POST {"NodePublic":"nodekey:<hex>","Source":"<ip>"} and expect a 200
// with {"Allow":true}. To use your own policy, replace authorizeFromEnv.
//
// Unlike derper, which defaults to fail open, this relay always fails
// closed: no admission configured, an unreachable controller, a timeout,
// a non-200 status or a malformed answer all reject the client.

export interface AuthorizeRequest {
  nodePublic: string; // "nodekey:<64 hex>"
  source: string; // client IP, or "" if unknown
}

// Authorize resolves true to admit and false to deny. It throws when it
// cannot decide; the relay treats that as a rejection too.
export type Authorize = (req: AuthorizeRequest) => Promise<boolean>;

export interface AdmissionEnv {
  // Service binding to an admission Worker. Preferred: needs no public URL.
  ADMISSION?: Fetcher;
  // URL of an admission controller, used when ADMISSION is not bound.
  ADMISSION_URL?: string;
}

// derper waits 5s for the admission controller.
const ADMISSION_TIMEOUT_MS = 5_000;

export class AdmissionError extends Error {}

export function authorizeFromEnv(env: AdmissionEnv): Authorize {
  const binding = env.ADMISSION;
  const url = env.ADMISSION_URL;
  if (!binding && !url) {
    return async () => {
      throw new AdmissionError("no admission controller configured (bind ADMISSION or set ADMISSION_URL)");
    };
  }
  return async ({ nodePublic, source }) => {
    const init: RequestInit = {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ NodePublic: nodePublic, Source: source }),
      signal: AbortSignal.timeout(ADMISSION_TIMEOUT_MS),
    };
    let res: Response;
    try {
      // A service binding needs a URL, but only the path reaches the Worker.
      res = binding ? await binding.fetch("https://admission/", init) : await fetch(url!, init);
    } catch (e) {
      throw new AdmissionError(`admission controller unreachable: ${e}`);
    }
    if (res.status !== 200) {
      throw new AdmissionError(`admission controller: ${res.status} ${res.statusText}`);
    }
    let body: unknown;
    try {
      body = JSON.parse((await res.text()).slice(0, 4096));
    } catch (e) {
      throw new AdmissionError(`admission controller: bad JSON: ${e}`);
    }
    const allow = (body as { Allow?: unknown } | null)?.Allow;
    if (typeof allow !== "boolean" && allow !== undefined) {
      throw new AdmissionError("admission controller: Allow is not a boolean");
    }
    // derper treats a missing Allow as false.
    return allow === true;
  };
}
