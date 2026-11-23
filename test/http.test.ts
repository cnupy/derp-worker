import { SELF, env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../src/index";
import { STATS_TOKEN } from "./keys";

const base = "https://relay.test";

type DerpMap = { Regions: Record<string, { Nodes: Record<string, unknown>[] }> };

describe("HTTP routes", () => {
  it("answers the probe paths", async () => {
    for (const path of ["/derp/probe", "/derp/latency-check"]) {
      const res = await SELF.fetch(base + path);
      expect(res.status).toBe(200);
      expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    }
    const post = await SELF.fetch(base + "/derp/probe", { method: "POST" });
    expect(post.status).toBe(405);
  });

  it("echoes a valid /generate_204 challenge", async () => {
    const res = await SELF.fetch(base + "/generate_204", { headers: { "X-Tailscale-Challenge": "abc.DEF_1:2-3" } });
    expect(res.status).toBe(204);
    expect(res.headers.get("X-Tailscale-Response")).toBe("response abc.DEF_1:2-3");
  });

  it("ignores a bad /generate_204 challenge", async () => {
    for (const ch of ["has space", "x".repeat(65)]) {
      const res = await SELF.fetch(base + "/generate_204", { headers: { "X-Tailscale-Challenge": ch } });
      expect(res.status).toBe(204);
      expect(res.headers.get("X-Tailscale-Response")).toBeNull();
    }
  });

  it("refuses /derp without a WebSocket upgrade", async () => {
    expect((await SELF.fetch(base + "/derp")).status).toBe(426);
    const noProto = await SELF.fetch(base + "/derp", { headers: { Upgrade: "websocket" } });
    expect(noProto.status).toBe(426);
    const rawDerp = await SELF.fetch(base + "/derp", { headers: { Upgrade: "DERP" } });
    expect(rawDerp.status).toBe(426);
  });
});

describe("/derpmap.json", () => {
  it("lists the relay node and the STUN servers", async () => {
    const res = await SELF.fetch(base + "/derpmap.json");
    const map = await res.json<DerpMap>();
    const nodes = map.Regions["900"].Nodes;
    expect(nodes[0]).toMatchObject({ HostName: "relay.test", STUNPort: -1, DERPPort: 443 });
    expect(nodes.slice(1)).toEqual([
      expect.objectContaining({ HostName: "stun.example.net", STUNPort: 3478 }),
      expect.objectContaining({ HostName: "stun2.example.net", STUNPort: 3478 }),
    ]);
  });

  it("has only the relay node without STUN_SERVERS", async () => {
    const res = await worker.fetch(new Request("http://relay.test:8787/derpmap.json"), { ...env, STUN_SERVERS: "" });
    const map = await res.json<DerpMap>();
    expect(map.Regions["900"].Nodes).toEqual([expect.objectContaining({ HostName: "relay.test", DERPPort: 8787 })]);
  });

  it("skips malformed STUN entries", async () => {
    const res = await worker.fetch(new Request(base + "/derpmap.json"), {
      ...env,
      STUN_SERVERS: "ok.example:3478,bad.example:99999,:3478",
    });
    const map = await res.json<DerpMap>();
    expect(map.Regions["900"].Nodes.map((n) => n.HostName)).toEqual(["relay.test", "ok.example"]);
  });
});

describe("/stats", () => {
  it("is 404 when STATS_TOKEN is not set", async () => {
    const res = await worker.fetch(new Request(base + "/stats"), { ...env, STATS_TOKEN: "" });
    expect(res.status).toBe(404);
    const withToken = await worker.fetch(
      new Request(base + "/stats", { headers: { Authorization: "Bearer anything" } }),
      { ...env, STATS_TOKEN: "" },
    );
    expect(withToken.status).toBe(404);
  });

  it("is 401 without the right token", async () => {
    expect((await SELF.fetch(base + "/stats")).status).toBe(401);
    for (const auth of ["Bearer wrong", `Bearer ${STATS_TOKEN}x`, STATS_TOKEN, "Basic abc"]) {
      const res = await SELF.fetch(base + "/stats", { headers: { Authorization: auth } });
      expect(res.status, auth).toBe(401);
    }
  });

  it("answers with the right token", async () => {
    const res = await SELF.fetch(base + "/stats", { headers: { Authorization: `Bearer ${STATS_TOKEN}` } });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ connected: 0 });
  });
});
