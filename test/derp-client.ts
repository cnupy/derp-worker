// A minimal DERP client for tests. It speaks just enough of the protocol to
// drive the relay over WebSocket: frames, the handshake, and close events.

import { SELF } from "cloudflare:test";
import nacl from "tweetnacl";
import type { TestKey } from "./keys";

export const F = {
  ServerKey: 0x01,
  ClientInfo: 0x02,
  ServerInfo: 0x03,
  SendPacket: 0x04,
  RecvPacket: 0x05,
  KeepAlive: 0x06,
  PeerGone: 0x08,
  Ping: 0x12,
  Pong: 0x13,
} as const;

export const MAGIC = new TextEncoder().encode("DERP🔑");

export interface Frame {
  type: number;
  body: Uint8Array;
}

export function frame(type: number, ...parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(5 + len);
  out[0] = type;
  new DataView(out.buffer).setUint32(1, len);
  let off = 5;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  return frame(0, ...parts).subarray(5);
}

// clientInfoFrame seals {"version":2} to the server the way derp.Client does:
// client public key, then nonce || box(json).
export function clientInfoFrame(key: TestKey, serverPub: Uint8Array): Uint8Array {
  const msg = new TextEncoder().encode(JSON.stringify({ version: 2, CanAckPings: true }));
  const nonce = nacl.randomBytes(24);
  return frame(F.ClientInfo, key.pub, nonce, nacl.box(msg, nonce, serverPub, key.priv));
}

export class TestConn {
  readonly ws: WebSocket;
  private buf: Uint8Array = new Uint8Array(0);
  private frames: Frame[] = [];
  private waiters: (() => void)[] = [];
  closed: { code: number; reason: string } | undefined;
  serverPub: Uint8Array | undefined;

  private constructor(ws: WebSocket) {
    this.ws = ws;
    ws.addEventListener("message", (e) => {
      const data: unknown = e.data;
      if (typeof data === "string") return;
      this.buf = concat(this.buf, new Uint8Array(data as ArrayBuffer));
      for (;;) {
        if (this.buf.length < 5) break;
        const len = new DataView(this.buf.buffer, this.buf.byteOffset + 1, 4).getUint32(0);
        if (this.buf.length < 5 + len) break;
        this.frames.push({ type: this.buf[0], body: this.buf.slice(5, 5 + len) });
        this.buf = this.buf.slice(5 + len);
      }
      this.wake();
    });
    ws.addEventListener("close", (e) => {
      this.closed = { code: e.code, reason: e.reason };
      this.wake();
    });
  }

  private wake() {
    const w = this.waiters;
    this.waiters = [];
    for (const f of w) f();
  }

  // open connects to /derp and accepts the WebSocket.
  static async open(): Promise<TestConn> {
    const res = await SELF.fetch("https://relay.test/derp", {
      headers: { Upgrade: "websocket", "Sec-WebSocket-Protocol": "derp" },
    });
    const ws = res.webSocket;
    if (res.status !== 101 || !ws) throw new Error(`upgrade failed: ${res.status}`);
    // With this compatibility date binary messages arrive as Blobs by
    // default; ArrayBuffers keep the frame parsing synchronous.
    ws.binaryType = "arraybuffer";
    ws.accept();
    return new TestConn(ws);
  }

  // connect opens a connection and finishes the handshake as key.
  static async connect(key: TestKey): Promise<TestConn> {
    const c = await TestConn.open();
    await c.handshake(key);
    return c;
  }

  send(b: Uint8Array) {
    this.ws.send(b);
  }

  // next returns the next frame, failing if none arrives in time.
  async next(timeoutMs = 2000): Promise<Frame> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const f = this.frames.shift();
      if (f) return f;
      if (this.closed) throw new Error(`connection closed: ${this.closed.code} ${this.closed.reason}`);
      if (Date.now() >= deadline) throw new Error("no frame in time");
      await this.waitEvent(deadline);
    }
  }

  // nextOf skips keepalives and returns the next frame of another type.
  async nextOf(type: number, timeoutMs = 2000): Promise<Frame> {
    for (;;) {
      const f = await this.next(timeoutMs);
      if (f.type === F.KeepAlive) continue;
      if (f.type !== type) throw new Error(`got frame type ${f.type}, want ${type}`);
      return f;
    }
  }

  // closedWith waits for the server to close the connection.
  async closedWith(timeoutMs = 2000): Promise<{ code: number; reason: string }> {
    const deadline = Date.now() + timeoutMs;
    while (!this.closed) {
      if (Date.now() >= deadline) throw new Error("connection still open");
      await this.waitEvent(deadline);
    }
    return this.closed;
  }

  private waitEvent(deadline: number): Promise<void> {
    return new Promise((resolve) => {
      const t = setTimeout(resolve, Math.max(0, deadline - Date.now()));
      this.waiters.push(() => {
        clearTimeout(t);
        resolve();
      });
    });
  }

  // handshake reads the ServerKey frame, sends the client info and opens
  // the sealed ServerInfo reply.
  async handshake(key: TestKey): Promise<unknown> {
    const sk = await this.nextOf(F.ServerKey);
    this.serverPub = sk.body.slice(8, 40);
    this.send(clientInfoFrame(key, this.serverPub));
    return this.readServerInfo(key.priv);
  }

  async readServerInfo(clientPriv: Uint8Array): Promise<unknown> {
    if (!this.serverPub) throw new Error("no server key yet");
    const si = await this.nextOf(F.ServerInfo);
    const opened = nacl.box.open(si.body.subarray(24), si.body.subarray(0, 24), this.serverPub, clientPriv);
    if (!opened) throw new Error("ServerInfo does not open");
    return JSON.parse(new TextDecoder().decode(opened));
  }

  close() {
    this.ws.close(1000, "done");
  }
}
