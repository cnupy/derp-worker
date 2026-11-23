// Bindings the tests see, from wrangler.jsonc plus vitest.config.ts.
declare namespace Cloudflare {
  interface Env {
    RELAY: DurableObjectNamespace<import("../src/index").Relay>;
    ADMISSION: Fetcher;
    STATS_TOKEN: string;
    STUN_SERVERS: string;
  }
}
