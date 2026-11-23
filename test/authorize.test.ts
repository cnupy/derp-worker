import { afterEach, describe, expect, it, vi } from "vitest";
import { AdmissionError, authorizeFromEnv } from "../src/authorize";

const req = { nodePublic: `nodekey:${"ab".repeat(32)}`, source: "192.0.2.1" };

// binding returns a fake service binding that answers with handler and
// records what it was sent.
function binding(handler: (r: Request) => Response | Promise<Response>) {
  const seen: { url: string; body: unknown }[] = [];
  const fetcher = {
    async fetch(input: RequestInfo | URL, init?: RequestInit) {
      const r = new Request(input, init);
      seen.push({ url: r.url, body: await r.clone().json() });
      return handler(r);
    },
  } as unknown as Fetcher;
  return { fetcher, seen };
}

describe("authorizeFromEnv", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("rejects when nothing is configured", async () => {
    await expect(authorizeFromEnv({})(req)).rejects.toThrow(AdmissionError);
    await expect(authorizeFromEnv({})(req)).rejects.toThrow(/no admission controller configured/);
  });

  it("admits on Allow true and sends derper's request shape", async () => {
    const b = binding(() => Response.json({ Allow: true }));
    await expect(authorizeFromEnv({ ADMISSION: b.fetcher })(req)).resolves.toBe(true);
    expect(b.seen).toEqual([{ url: "https://admission/", body: { NodePublic: req.nodePublic, Source: req.source } }]);
  });

  it("denies on Allow false", async () => {
    const b = binding(() => Response.json({ Allow: false }));
    await expect(authorizeFromEnv({ ADMISSION: b.fetcher })(req)).resolves.toBe(false);
  });

  it("denies when Allow is missing, as derper does", async () => {
    const b = binding(() => Response.json({}));
    await expect(authorizeFromEnv({ ADMISSION: b.fetcher })(req)).resolves.toBe(false);
  });

  it("rejects a non-boolean Allow", async () => {
    const b = binding(() => Response.json({ Allow: "yes" }));
    await expect(authorizeFromEnv({ ADMISSION: b.fetcher })(req)).rejects.toThrow(/Allow is not a boolean/);
  });

  it("rejects a non-200 answer", async () => {
    const b = binding(() => new Response("nope", { status: 500 }));
    await expect(authorizeFromEnv({ ADMISSION: b.fetcher })(req)).rejects.toThrow(/500/);
  });

  it("rejects bad JSON", async () => {
    const b = binding(() => new Response("{not json", { status: 200 }));
    await expect(authorizeFromEnv({ ADMISSION: b.fetcher })(req)).rejects.toThrow(/bad JSON/);
  });

  it("rejects an unreachable controller", async () => {
    const b = binding(() => {
      throw new Error("connection refused");
    });
    await expect(authorizeFromEnv({ ADMISSION: b.fetcher })(req)).rejects.toThrow(/unreachable/);
  });

  it("rejects when the controller does not answer in time", async () => {
    const fetcher = {
      fetch: (_input: RequestInfo | URL, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new Error(String(init.signal?.reason))));
        }),
    } as unknown as Fetcher;
    await expect(authorizeFromEnv({ ADMISSION: fetcher }, 50)(req)).rejects.toThrow(/unreachable/);
  });

  it("uses ADMISSION_URL when no binding is set", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockImplementation(() => Promise.resolve(Response.json({ Allow: true })));
    await expect(authorizeFromEnv({ ADMISSION_URL: "https://admission.example/check" })(req)).resolves.toBe(true);
    expect(spy).toHaveBeenCalledOnce();
    expect(spy.mock.calls[0][0] as string).toBe("https://admission.example/check");
  });

  it("prefers the binding over ADMISSION_URL", async () => {
    const spy = vi.spyOn(globalThis, "fetch");
    const b = binding(() => Response.json({ Allow: true }));
    await expect(
      authorizeFromEnv({ ADMISSION: b.fetcher, ADMISSION_URL: "https://admission.example/" })(req),
    ).resolves.toBe(true);
    expect(spy).not.toHaveBeenCalled();
  });
});
