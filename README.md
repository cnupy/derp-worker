# derp-worker

A DERP relay that runs on Cloudflare Workers with one Durable Object. Use it as a private relay for [tailcat](https://github.com/tailscale/tailcat) or other clients of Tailscale's DERP protocol.

Workers can't take over a raw TCP connection, so the relay speaks DERP over WebSocket only (path `/derp`, subprotocol `derp`, the same as derper's WebSocket mode). A client needs WebSocket DERP support. The `tailscale.com/feature/derpwebsocket` package adds it: when the normal `Upgrade: DERP` request fails, the client retries over WebSocket by itself. tailcat v0.8.0 and later link it in. tailscaled and tsnet don't, as far as I know.

## What it does

- DERP protocol version 2: server key, client info, server info, send and receive packets, ping and pong, keepalive every 55 s, peer gone.
- Asks an admission controller before it accepts a client key. With no controller configured it rejects every client.
- Answers the probe paths clients use: `/derp/probe`, `/derp/latency-check` and `/generate_204`.
- Serves a one-region DERP map at `/derpmap.json`.
- Keeps hourly counters, readable at `/stats` with a token.

It does not do STUN (Workers have no UDP), mesh between relays, raw `Upgrade: DERP`, or rate limits. All clients share one Durable Object.

## Setup

```sh
npm install
npx wrangler deploy
```

Then configure admission, below. Until you do, every client is rejected.

Optional settings:

| Name            | Kind            | What it does                                                                       |
| --------------- | --------------- | ---------------------------------------------------------------------------------- |
| `ADMISSION`     | service binding | Worker that answers admission requests. Preferred, because it needs no public URL. |
| `ADMISSION_URL` | var             | URL of an admission controller, used when `ADMISSION` is not bound.                |
| `STUN_SERVERS`  | var             | Comma-separated `host:port` list. Each one becomes a STUN node in `/derpmap.json`. |
| `STATS_TOKEN`   | secret          | Turns on `/stats`. Without it `/stats` returns 404.                                |

The settings are commented out in `wrangler.jsonc`. Set secrets with `npx wrangler secret put <NAME>`.

### Admission

The relay uses derper's admission controller protocol, the one behind derper's `--verify-client-url`. For each new client it POSTs:

```json
{ "NodePublic": "nodekey:<64 hex>", "Source": "<client IP>" }
```

and expects status 200 with:

```json
{ "Allow": true }
```

A missing `Allow` counts as false, as in derper. Unlike derper, this relay fails closed: an unreachable controller, a timeout after 5 s, a status other than 200, or a body it can't parse all reject the client.

`examples/admission` is a small controller that reads its allowlist from an `ALLOWED_KEYS` secret. Deploy it, bind it to the relay as `ADMISSION`, and set the keys:

```sh
cd examples/admission
npm install
npx wrangler deploy
npx wrangler secret put ALLOWED_KEYS   # nodekey:<hex>,nodekey:<hex>
```

Changing the secret redeploys only the admission Worker. Clients already connected to the relay stay connected. Removing a key does not drop a client that is already connected; it is refused at its next connect.

To use another policy, replace `authorizeFromEnv` in `src/authorize.ts`.

A rejected client gets a WebSocket close with status 1008 and reason `not allowed` (or `admission check failed` when the controller can't answer). The relay holds a rejected socket for 5 s before it closes it. Without that delay a rejected client redials several times a second, because magicsock retries a broken DERP connection after 10 ms, then 40 ms, 90 ms and so on.

### DERP map and STUN

Clients need STUN to find their public address for direct connections, and this relay can't answer it. List public STUN servers as extra nodes after the relay node, in the same region:

```json
{
  "Regions": {
    "900": {
      "RegionID": 900,
      "RegionCode": "cf",
      "RegionName": "Cloudflare Worker",
      "Nodes": [
        {
          "Name": "900a",
          "RegionID": 900,
          "HostName": "derp-worker.example.workers.dev",
          "STUNPort": -1,
          "DERPPort": 443
        },
        { "Name": "900stun1", "RegionID": 900, "HostName": "stun.cloudflare.com", "STUNPort": 3478 }
      ]
    }
  }
}
```

`/derpmap.json` returns this shape for the host it was fetched from, with one STUN node per entry in `STUN_SERVERS`.

The STUN entries are plain nodes, not `STUNOnly` ones, because tailcat drops `STUNOnly` nodes from its addresses. That is safe here: a WebSocket DERP client only dials the first node of a region.

Keep at least one STUN server in the list. See the known issue below.

### Stats

```sh
curl -H "Authorization: Bearer $STATS_TOKEN" https://<your worker>/stats
```

Returns the number of connected clients and hourly counters: messages and bytes in, packets relayed, connects, rejects and so on.

## Development

```sh
npm ci
npm run check         # type-check the relay, the tests and the example
npm run lint          # ESLint with typescript-eslint's type-aware rules
npm run format:check  # Prettier; `npm run format` rewrites the files
npm test              # unit and integration tests
npm run test:e2e      # end-to-end test, needs Go
```

`npm test` runs inside workerd through Vitest, so it needs no Cloudflare account. The tests drive the relay with a small DERP client over WebSocket: handshake, relaying, ping, peer-gone, rejected keys and the handshake timeout. The handshake test replays a ClientInfo frame that Tailscale's own `derp.Client` sealed. It lives in `test/fixtures/handshake.json`, with the generator in `test/fixtures/gen`. Its keys are throwaway test keys.

`npm run test:e2e` starts `wrangler dev` with the relay and the example admission Worker, then runs a tailcat v0.8.0 server and client through it. It checks an echo between two allowed keys and that the relay refuses a third key. It takes about 30 seconds. CI runs it only when the workflow is started by hand.

`.npmrc` sets `legacy-peer-deps`, because npm 11 crashes while resolving Vitest's optional peer dependencies.

## Known issues

- With no STUN server in the region, the relay connection drops every 20 to 30 seconds while traffic flows. netcheck finds no way to send IPv4, magicsock rebinds, and a rebind closes a WebSocket DERP connection because it has no local address. Listing STUN servers avoids the trigger. A real network change, such as a Wi-Fi switch, still causes one drop. Upstream issue pending.
- Partial frames are kept in memory. If the Durable Object hibernates in the middle of a frame, which takes 10 s without a message, that frame is lost.
- All clients go through one Durable Object, so one Cloudflare location handles all traffic.

## License

BSD-3-Clause, see [LICENSE](LICENSE).

The protocol implementation follows Tailscale's derper source (BSD-3-Clause) as its spec. It copies no code from it.
