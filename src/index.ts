// A DERP relay as a Worker plus one Durable Object.
// It speaks the DERP protocol (tailscale.com/derp, protocol version 2) over
// WebSocket with subprotocol "derp", the way derper's AddWebSocketSupport
// does. Tailscale's derper source is the spec; no code is copied from it.
// Mesh, watch-conns and forward-packet frames are ignored.

import { DurableObject } from "cloudflare:workers";
import nacl from "tweetnacl";
import { AdmissionError, type AdmissionEnv, type Authorize, authorizeFromEnv } from "./authorize";

interface Env extends AdmissionEnv {
  RELAY: DurableObjectNamespace<Relay>;
  // Secret. When set, /stats answers requests that carry
  // "Authorization: Bearer <STATS_TOKEN>". When unset, /stats is 404.
  STATS_TOKEN?: string;
  // Comma-separated host:port STUN servers to list in /derpmap.json.
  STUN_SERVERS?: string;
}

// Frame types from derp/derp.go.
const F = {
  ServerKey: 0x01,
  ClientInfo: 0x02,
  ServerInfo: 0x03,
  SendPacket: 0x04,
  RecvPacket: 0x05,
  KeepAlive: 0x06,
  NotePreferred: 0x07,
  PeerGone: 0x08,
  Ping: 0x12,
  Pong: 0x13,
} as const;

const MAGIC = new TextEncoder().encode("DERP🔑"); // 8 bytes
const KEY_LEN = 32;
const NONCE_LEN = 24;
const HDR_LEN = 5;
const MAX_PACKET = 64 << 10;
const MAX_CLIENT_INFO = 256 << 10;
const PROTOCOL_VERSION = 2;
const PEER_GONE_DISCONNECTED = 0x00;
const PEER_GONE_NOT_HERE = 0x01;
// derp clients drop the connection after 120s with no frame; derper sends
// a keepalive every 60s.
const KEEPALIVE_MS = 55_000;
const REGION_ID = 900;
// Sockets that never send their client info are closed after this long.
// derper allows 10s; this is longer because the alarm that enforces it
// can fire late.
const HANDSHAKE_MS = 30_000;
// A rejected socket stays open this long before it is closed with a
// reason (see onClientInfo).
const REJECT_DELAY_MS = 5_000;

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (s: string) => Uint8Array.from(s.match(/../g) ?? [], (x) => parseInt(x, 16));

function frame(type: number, ...parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(HDR_LEN + len);
  out[0] = type;
  new DataView(out.buffer).setUint32(1, len);
  let off = HDR_LEN;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// box seals like key.NodePrivate.SealTo: nonce || box(msg).
function seal(msg: Uint8Array, theirPub: Uint8Array, ourPriv: Uint8Array): Uint8Array {
  const nonce = nacl.randomBytes(NONCE_LEN);
  const box = nacl.box(msg, nonce, theirPub, ourPriv);
  const out = new Uint8Array(NONCE_LEN + box.length);
  out.set(nonce);
  out.set(box, NONCE_LEN);
  return out;
}

// Attachment kept with each hibernatable socket. key is set once the
// handshake is done.
interface Att {
  key?: string;
  rejected?: boolean;
  // For a rejected socket: when to close it, and the close reason.
  closeAt?: number;
  reason?: string;
  // Client IP from CF-Connecting-IP, passed to the admission check.
  source?: string;
  // When the socket was accepted, in ms since epoch. Sockets with no key
  // after HANDSHAKE_MS are closed.
  opened?: number;
}

type Counters = Record<string, number>;

export class Relay extends DurableObject<Env> {
  private priv!: Uint8Array;
  private pub!: Uint8Array;
  private authorize: Authorize;
  // Unprocessed bytes per socket: partial frames, and whole frames that
  // arrive while the socket's admission check runs. Lost if the object
  // hibernates mid-frame, which needs 10s of silence in the middle of a frame.
  private bufs = new Map<WebSocket, Uint8Array>();
  // Sockets whose admission check is running.
  private pending = new Set<WebSocket>();
  private byKey = new Map<string, WebSocket>();
  // dst key -> keys that sent to it, so they hear PeerGone when it leaves.
  private sentTo = new Map<string, Set<string>>();
  private notHereSent = new Map<string, number>();
  private counts: Counters = {};
  private lastFlush = 0;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.authorize = authorizeFromEnv(env);
    ctx.blockConcurrencyWhile(async () => {
      let sk = await ctx.storage.get<string>("serverPrivateKey");
      if (!sk) {
        sk = hex(nacl.box.keyPair().secretKey);
        await ctx.storage.put("serverPrivateKey", sk);
      }
      const kp = nacl.box.keyPair.fromSecretKey(unhex(sk));
      this.priv = kp.secretKey;
      this.pub = kp.publicKey;
      ctx.storage.sql.exec(
        "CREATE TABLE IF NOT EXISTS stats (hour TEXT, name TEXT, n INTEGER, PRIMARY KEY (hour, name))",
      );
    });
    // Rebuild the key map after waking from hibernation.
    for (const ws of ctx.getWebSockets()) {
      const att = ws.deserializeAttachment() as Att | null;
      if (att?.key) this.byKey.set(att.key, ws);
    }
  }

  private count(name: string, n = 1) {
    this.counts[name] = (this.counts[name] ?? 0) + n;
    // Each flush writes one SQLite row per counter name, so flush at most
    // once a minute.
    if (Date.now() - this.lastFlush > 60_000) this.flush();
  }

  private flush() {
    this.lastFlush = Date.now();
    const hour = new Date().toISOString().slice(0, 13);
    const entries = Object.entries(this.counts);
    // Count the rows this flush writes, including its own counter row.
    const rows = entries.length + (entries.length ? 1 : 0);
    if (rows) entries.push(["stats_rows_written", rows]);
    for (const [name, n] of entries) {
      this.ctx.storage.sql.exec(
        "INSERT INTO stats (hour, name, n) VALUES (?, ?, ?) ON CONFLICT (hour, name) DO UPDATE SET n = n + excluded.n",
        hour,
        name,
        n,
      );
    }
    this.counts = {};
  }

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === "/stats") {
      this.flush();
      const rows = this.ctx.storage.sql
        .exec("SELECT hour, name, n FROM stats ORDER BY hour, name")
        .toArray();
      return Response.json({ connected: this.byKey.size, rows });
    }
    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];
    this.ctx.acceptWebSocket(server);
    server.serializeAttachment({
      opened: Date.now(),
      source: req.headers.get("CF-Connecting-IP") ?? "",
    } satisfies Att);
    this.count("ws_accept");
    await this.scheduleAlarm(Date.now() + HANDSHAKE_MS);
    // FrameServerKey: magic + server public key.
    server.send(frame(F.ServerKey, MAGIC, this.pub));
    return new Response(null, {
      status: 101,
      webSocket: client,
      headers: { "Sec-WebSocket-Protocol": "derp" },
    });
  }

  async webSocketMessage(ws: WebSocket, msg: ArrayBuffer | string) {
    if (typeof msg === "string") {
      ws.close(1003, "binary only");
      return;
    }
    this.count("ws_msg_in");
    this.count("ws_bytes_in", msg.byteLength);
    if ((ws.deserializeAttachment() as Att | null)?.rejected) return;
    this.append(ws, new Uint8Array(msg));
    // While the admission check runs, frames only queue up. The running
    // drain picks them up in order once the check is done.
    if (this.pending.has(ws)) return;
    await this.drain(ws);
  }

  private append(ws: WebSocket, b: Uint8Array) {
    const prev = this.bufs.get(ws);
    if (!prev?.length) {
      this.bufs.set(ws, b);
      return;
    }
    const joined = new Uint8Array(prev.length + b.length);
    joined.set(prev);
    joined.set(b, prev.length);
    this.bufs.set(ws, joined);
  }

  // drain handles every complete frame buffered for ws, in order. For the
  // first frame it awaits the admission check; other sockets keep being
  // served meanwhile, and frames for ws that arrive during the wait are
  // appended to its buffer and handled after.
  private async drain(ws: WebSocket) {
    for (;;) {
      const buf = this.bufs.get(ws);
      if (!buf || buf.length < HDR_LEN) return;
      const type = buf[0];
      const len = new DataView(buf.buffer, buf.byteOffset + 1, 4).getUint32(0);
      if (len > MAX_CLIENT_INFO) {
        this.bufs.delete(ws);
        ws.close(1009, "frame too large");
        return;
      }
      if (buf.length - HDR_LEN < len) return;
      const body = buf.subarray(HDR_LEN, HDR_LEN + len);
      const rest = buf.subarray(HDR_LEN + len);
      if (rest.length) this.bufs.set(ws, rest);
      else this.bufs.delete(ws);
      this.count("frames_in");
      const att = (ws.deserializeAttachment() as Att | null) ?? {};
      let ok: boolean;
      if (att.key) {
        ok = this.onFrame(ws, att.key, type, body);
      } else {
        this.pending.add(ws);
        try {
          ok = await this.onClientInfo(ws, type, body, att);
        } finally {
          this.pending.delete(ws);
        }
      }
      if (!ok) {
        this.bufs.delete(ws);
        return;
      }
    }
  }

  // onFrame handles one frame from an admitted client. It returns false if
  // it closed the socket.
  private onFrame(ws: WebSocket, key: string, type: number, body: Uint8Array): boolean {
    switch (type) {
      case F.SendPacket:
        this.onSendPacket(ws, key, body);
        return true;
      case F.Ping:
        if (body.length < 8 || body.length > 1000) {
          ws.close(1002, "bad ping");
          return false;
        }
        this.count("pings");
        ws.send(frame(F.Pong, body.subarray(0, 8)));
        return true;
      case F.NotePreferred:
        return true;
      default:
        this.count("frames_ignored");
        return true;
    }
  }

  // onClientInfo handles the handshake frame and asks the admission check.
  // It returns false if the client is not admitted.
  private async onClientInfo(ws: WebSocket, type: number, body: Uint8Array, att: Att): Promise<boolean> {
    if (type !== F.ClientInfo || body.length < KEY_LEN + NONCE_LEN) {
      ws.close(1002, "want client info");
      return false;
    }
    const clientPub = body.slice(0, KEY_LEN);
    const boxed = body.subarray(KEY_LEN);
    const opened = nacl.box.open(
      boxed.subarray(NONCE_LEN),
      boxed.subarray(0, NONCE_LEN),
      clientPub,
      this.priv,
    );
    if (!opened) {
      this.count("reject_badbox");
      ws.close(1008, "bad client info");
      return false;
    }
    const key = hex(clientPub);
    let reason = "";
    let closeReason = "";
    try {
      if (!(await this.authorize({ nodePublic: `nodekey:${key}`, source: att.source ?? "" }))) {
        this.count("reject_denied");
        reason = "denied by admission controller";
        closeReason = "not allowed";
      }
    } catch (e) {
      this.count("reject_admission_error");
      reason = e instanceof AdmissionError ? e.message : `admission check failed: ${e}`;
      closeReason = "admission check failed";
    }
    if (ws.readyState !== WebSocket.READY_STATE_OPEN) return false; // closed during the check
    if (reason) {
      console.log(`rejected client nodekey:${key} from ${att.source || "?"}: ${reason}`);
      // Close with a reason the client can log, but not at once. A derp
      // client counts the connection as up as soon as it has sent its
      // client info. When it breaks, magicsock retries after 10ms, 40ms,
      // 90ms and so on (n^2 x 10ms, at most 5s), and every packet it wants
      // to send also triggers a redial. An immediate close would make a
      // rejected client redial several times a second. Holding the socket
      // for REJECT_DELAY_MS caps that at about one attempt per delay.
      ws.serializeAttachment({
        rejected: true,
        closeAt: Date.now() + REJECT_DELAY_MS,
        reason: closeReason,
        opened: att.opened,
        source: att.source,
      } satisfies Att);
      await this.scheduleAlarm(Date.now() + REJECT_DELAY_MS);
      return false;
    }
    this.count("admit_ok");
    const old = this.byKey.get(key);
    if (old && old !== ws) old.close(1000, "replaced by newer connection");
    this.byKey.set(key, ws);
    ws.serializeAttachment({ key } satisfies Att);
    this.count("connects");
    const info = new TextEncoder().encode(JSON.stringify({ version: PROTOCOL_VERSION }));
    ws.send(frame(F.ServerInfo, seal(info, clientPub, this.priv)));
    this.ensureAlarm();
    return true;
  }

  private onSendPacket(ws: WebSocket, src: string, body: Uint8Array) {
    if (body.length < KEY_LEN || body.length - KEY_LEN > MAX_PACKET) {
      ws.close(1002, "bad send packet");
      return;
    }
    const dst = hex(body.subarray(0, KEY_LEN));
    const dstWS = this.byKey.get(dst);
    if (!dstWS) {
      this.count("pkt_drop_nothere");
      // derper limits these replies; one per second per pair is plenty.
      const k = src + dst;
      const now = Date.now();
      if ((this.notHereSent.get(k) ?? 0) < now - 1000) {
        this.notHereSent.set(k, now);
        ws.send(frame(F.PeerGone, body.subarray(0, KEY_LEN), Uint8Array.of(PEER_GONE_NOT_HERE)));
      }
      return;
    }
    let senders = this.sentTo.get(dst);
    if (!senders) this.sentTo.set(dst, (senders = new Set()));
    senders.add(src);
    this.count("pkt_relayed");
    this.count("pkt_bytes", body.length - KEY_LEN);
    dstWS.send(frame(F.RecvPacket, unhex(src), body.subarray(KEY_LEN)));
  }

  private gone(ws: WebSocket) {
    this.bufs.delete(ws);
    const att = ws.deserializeAttachment() as Att | null;
    const key = att?.key;
    if (!key || this.byKey.get(key) !== ws) return;
    this.byKey.delete(key);
    this.count("disconnects");
    const keyBytes = unhex(key);
    for (const src of this.sentTo.get(key) ?? []) {
      try {
        this.byKey.get(src)?.send(frame(F.PeerGone, keyBytes, Uint8Array.of(PEER_GONE_DISCONNECTED)));
      } catch {}
    }
    this.sentTo.delete(key);
    this.flush();
  }

  async webSocketClose(ws: WebSocket) {
    this.gone(ws);
  }

  async webSocketError(ws: WebSocket) {
    this.gone(ws);
  }

  private async ensureAlarm() {
    await this.scheduleAlarm(Date.now() + KEEPALIVE_MS);
  }

  // scheduleAlarm sets the alarm to at, unless one is already due sooner.
  private async scheduleAlarm(at: number) {
    const cur = await this.ctx.storage.getAlarm();
    if (cur == null || cur > at) await this.ctx.storage.setAlarm(at);
  }

  // alarm sends keepalives to connected clients, closes rejected sockets
  // once their delay is over, and closes sockets that never finished the
  // handshake.
  async alarm() {
    this.count("alarms");
    const now = Date.now();
    let next = this.byKey.size > 0 ? now + KEEPALIVE_MS : Infinity;
    const ka = frame(F.KeepAlive);
    for (const ws of this.byKey.values()) {
      try {
        ws.send(ka);
      } catch {}
    }
    for (const ws of this.ctx.getWebSockets()) {
      const att = ws.deserializeAttachment() as Att | null;
      if (att?.key) continue;
      const rejected = att?.rejected === true;
      const deadline = rejected ? (att?.closeAt ?? 0) : (att?.opened ?? 0) + HANDSHAKE_MS;
      if (deadline <= now) {
        this.count(rejected ? "rejects_closed" : "handshake_timeouts");
        this.bufs.delete(ws);
        try {
          ws.close(1008, rejected ? att?.reason || "not allowed" : "handshake timeout");
        } catch {}
      } else {
        next = Math.min(next, deadline);
      }
    }
    this.flush();
    if (next !== Infinity) await this.ctx.storage.setAlarm(next);
  }
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    switch (url.pathname) {
      case "/derp/probe":
      case "/derp/latency-check":
        if (req.method !== "GET" && req.method !== "HEAD") {
          return new Response("bogus probe method", { status: 405 });
        }
        return new Response(null, { status: 200, headers: { "Access-Control-Allow-Origin": "*" } });
      case "/generate_204": {
        const h = new Headers({ "Cache-Control": "no-cache, no-store, must-revalidate, no-transform, max-age=0" });
        const ch = req.headers.get("X-Tailscale-Challenge");
        if (ch && ch.length <= 64 && /^[A-Za-z0-9._:-]*$/.test(ch)) h.set("X-Tailscale-Response", "response " + ch);
        return new Response(null, { status: 204, headers: h });
      }
      case "/derpmap.json":
        return Response.json(derpMap(url, env.STUN_SERVERS));
      case "/stats":
        if (!env.STATS_TOKEN) return new Response("not found\n", { status: 404 });
        if (!bearerMatches(req, env.STATS_TOKEN)) {
          return new Response("unauthorized\n", { status: 401, headers: { "WWW-Authenticate": "Bearer" } });
        }
        return env.RELAY.get(env.RELAY.idFromName("relay")).fetch(req);
      case "/derp": {
        const up = (req.headers.get("Upgrade") ?? "").toLowerCase();
        const proto = req.headers.get("Sec-WebSocket-Protocol") ?? "";
        if (up !== "websocket" || !proto.split(",").map((s) => s.trim()).includes("derp")) {
          return new Response("DERP requires a WebSocket upgrade with subprotocol derp", { status: 426 });
        }
        return env.RELAY.get(env.RELAY.idFromName("relay")).fetch(req);
      }
      default:
        return new Response("DERP relay\n", { status: 200 });
    }
  },
};

// bearerMatches reports whether req carries "Authorization: Bearer <token>".
// The compare takes the same time whether or not the token matches.
function bearerMatches(req: Request, token: string): boolean {
  const got = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
  const enc = new TextEncoder();
  const a = enc.encode(got);
  const b = enc.encode(token);
  if (a.byteLength !== b.byteLength) {
    // timingSafeEqual needs equal lengths; compare b with itself so a wrong
    // length costs about as much as a wrong token.
    crypto.subtle.timingSafeEqual(b, b);
    return false;
  }
  return crypto.subtle.timingSafeEqual(a, b);
}

// derpMap describes this Worker as a one-region map. The first node is the
// relay. It has STUN off, because Workers cannot answer UDP. Each server in
// stunServers becomes an extra node after it. Clients use those only for
// STUN: a WebSocket DERP client dials only the first node of a region.
// They are plain nodes, not STUNOnly ones, because tailcat drops STUNOnly
// nodes from its addresses.
function derpMap(url: URL, stunServers?: string) {
  const port = url.port ? Number(url.port) : url.protocol === "http:" ? 80 : 443;
  const nodes: Record<string, unknown>[] = [
    {
      Name: `${REGION_ID}a`,
      RegionID: REGION_ID,
      HostName: url.hostname,
      STUNPort: -1,
      DERPPort: port,
      CanPort80: false,
    },
  ];
  for (const hp of (stunServers ?? "").split(",").map((s) => s.trim()).filter(Boolean)) {
    const i = hp.lastIndexOf(":");
    const host = i > 0 ? hp.slice(0, i) : hp;
    const stunPort = i > 0 ? Number(hp.slice(i + 1)) : 3478;
    if (!host || !Number.isInteger(stunPort) || stunPort <= 0 || stunPort > 65535) continue;
    nodes.push({
      Name: `${REGION_ID}stun${nodes.length}`,
      RegionID: REGION_ID,
      HostName: host,
      STUNPort: stunPort,
      CanPort80: false,
    });
  }
  return {
    Regions: {
      [REGION_ID]: {
        RegionID: REGION_ID,
        RegionCode: "cf",
        RegionName: "Cloudflare Worker",
        Nodes: nodes,
      },
    },
  };
}
