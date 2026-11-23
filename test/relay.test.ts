import { env, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import nacl from "tweetnacl";
import { describe, expect, it } from "vitest";
import fixture from "./fixtures/handshake.json";
import { F, MAGIC, TestConn, clientInfoFrame, concat, frame } from "./derp-client";
import { ALICE, BOB, STRANGER, unhex } from "./keys";

const relay = () => env.RELAY.get(env.RELAY.idFromName("relay"));

// useFixtureServerKey gives the relay the Go fixture's server key, so the
// sealed ClientInfo that derp.Client produced opens.
async function useFixtureServerKey() {
  await runInDurableObject(relay(), async (instance, state) => {
    await state.storage.put("serverPrivateKey", fixture.serverPrivate);
    await (instance as unknown as { loadServerKey(): Promise<void> }).loadServerKey();
  });
}

// expireSockets moves the deadlines of sockets that have no key into the
// past, then runs the relay's alarm, which closes them.
async function expireSockets() {
  await runInDurableObject(relay(), (_instance, state) => {
    for (const ws of state.getWebSockets()) {
      const att = ws.deserializeAttachment() as Record<string, unknown> | null;
      if (!att || att.key) continue;
      ws.serializeAttachment({ ...att, opened: 0, closeAt: att.rejected ? 0 : undefined });
    }
  });
  expect(await runDurableObjectAlarm(relay())).toBe(true);
}

// waitForPendingRejection waits until the relay has marked one socket as
// rejected, so the test can expire it.
async function waitForRejected() {
  for (let i = 0; i < 100; i++) {
    const n = await runInDurableObject(
      relay(),
      (_instance, state) =>
        state.getWebSockets().filter((ws) => (ws.deserializeAttachment() as { rejected?: boolean } | null)?.rejected)
          .length,
    );
    if (n > 0) return;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error("socket was never rejected");
}

describe("handshake", () => {
  it("sends the server key first", async () => {
    await useFixtureServerKey();
    const c = await TestConn.open();
    const f = await c.next();
    expect(f.type).toBe(F.ServerKey);
    expect(f.body.length).toBe(40);
    expect(f.body.slice(0, 8)).toEqual(MAGIC);
    expect(Array.from(frame(f.type, f.body))).toEqual(Array.from(unhex(fixture.serverKeyFrame)));
    c.close();
  });

  it("opens a ClientInfo sealed by tailscale.com's derp.Client", async () => {
    await useFixtureServerKey();
    const c = await TestConn.open();
    const sk = await c.nextOf(F.ServerKey);
    c.serverPub = sk.body.slice(8, 40);
    c.send(unhex(fixture.clientInfoFrame));
    expect(await c.readServerInfo(unhex(fixture.clientPrivate))).toEqual({ version: 2 });
    c.close();
  });

  it("reads a ClientInfo split over several messages", async () => {
    const c = await TestConn.open();
    const sk = await c.nextOf(F.ServerKey);
    c.serverPub = sk.body.slice(8, 40);
    const ci = clientInfoFrame(ALICE, c.serverPub);
    for (const cut of [
      [0, 3],
      [3, 40],
      [40, ci.length],
    ])
      c.send(ci.slice(cut[0], cut[1]));
    expect(await c.readServerInfo(ALICE.priv)).toEqual({ version: 2 });
    c.close();
  });

  it("closes a socket whose ClientInfo does not open", async () => {
    const c = await TestConn.open();
    await c.nextOf(F.ServerKey);
    // Sealed to the wrong server key.
    c.send(clientInfoFrame(ALICE, nacl.box.keyPair().publicKey));
    expect(await c.closedWith()).toEqual({ code: 1008, reason: "bad client info" });
  });

  it("closes a socket that sends something else first", async () => {
    const c = await TestConn.open();
    await c.nextOf(F.ServerKey);
    c.send(frame(F.Ping, new Uint8Array(8)));
    expect(await c.closedWith()).toEqual({ code: 1002, reason: "want client info" });
  });

  it("closes an oversized frame", async () => {
    const c = await TestConn.open();
    await c.nextOf(F.ServerKey);
    const hdr = new Uint8Array(5);
    hdr[0] = F.ClientInfo;
    new DataView(hdr.buffer).setUint32(1, (256 << 10) + 1);
    c.send(hdr);
    expect(await c.closedWith()).toEqual({ code: 1009, reason: "frame too large" });
  });

  it("closes a rejected key with a reason after the delay", async () => {
    const c = await TestConn.open();
    const sk = await c.nextOf(F.ServerKey);
    c.send(clientInfoFrame(STRANGER, sk.body.slice(8, 40)));
    await waitForRejected();
    expect(c.closed).toBeUndefined(); // held open until the delay is over
    await expireSockets();
    expect(await c.closedWith()).toEqual({ code: 1008, reason: "not allowed" });
  });

  it("closes a socket that never sends its ClientInfo", async () => {
    const c = await TestConn.open();
    await c.nextOf(F.ServerKey);
    await expireSockets();
    expect(await c.closedWith()).toEqual({ code: 1008, reason: "handshake timeout" });
  });
});

describe("relaying", () => {
  it("delivers a packet with the sender's key", async () => {
    const a = await TestConn.connect(ALICE);
    const b = await TestConn.connect(BOB);
    const payload = new TextEncoder().encode("hello bob");
    a.send(frame(F.SendPacket, BOB.pub, payload));
    const f = await b.nextOf(F.RecvPacket);
    expect(f.body.slice(0, 32)).toEqual(ALICE.pub);
    expect(new TextDecoder().decode(f.body.slice(32))).toBe("hello bob");
    a.close();
    b.close();
  });

  it("handles several frames in one message", async () => {
    const a = await TestConn.connect(ALICE);
    a.send(
      concat(
        frame(F.Ping, Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8)),
        frame(F.Ping, Uint8Array.of(9, 9, 9, 9, 9, 9, 9, 9)),
      ),
    );
    expect((await a.nextOf(F.Pong)).body).toEqual(Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8));
    expect((await a.nextOf(F.Pong)).body).toEqual(Uint8Array.of(9, 9, 9, 9, 9, 9, 9, 9));
    a.close();
  });

  it("answers a ping with a pong", async () => {
    const a = await TestConn.connect(ALICE);
    const data = Uint8Array.of(8, 7, 6, 5, 4, 3, 2, 1);
    a.send(frame(F.Ping, data));
    expect((await a.nextOf(F.Pong)).body).toEqual(data);
    a.close();
  });

  it("tells the sender when the destination is not connected", async () => {
    const a = await TestConn.connect(ALICE);
    a.send(frame(F.SendPacket, BOB.pub, Uint8Array.of(1)));
    const f = await a.nextOf(F.PeerGone);
    expect(f.body).toEqual(concat(BOB.pub, Uint8Array.of(0x01)));
    a.close();
  });

  it("tells the sender when its peer disconnects", async () => {
    const a = await TestConn.connect(ALICE);
    const b = await TestConn.connect(BOB);
    a.send(frame(F.SendPacket, BOB.pub, Uint8Array.of(1)));
    await b.nextOf(F.RecvPacket);
    b.close();
    const f = await a.nextOf(F.PeerGone);
    expect(f.body).toEqual(concat(BOB.pub, Uint8Array.of(0x00)));
    a.close();
  });

  it("replaces an older connection with the same key", async () => {
    const first = await TestConn.connect(ALICE);
    const second = await TestConn.connect(ALICE);
    expect(await first.closedWith()).toEqual({ code: 1000, reason: "replaced by newer connection" });
    second.close();
  });

  it("sends keepalives to connected clients", async () => {
    const a = await TestConn.connect(ALICE);
    expect(await runDurableObjectAlarm(relay())).toBe(true);
    expect((await a.next()).type).toBe(F.KeepAlive);
    a.close();
  });
});
