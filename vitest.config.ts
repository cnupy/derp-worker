import { readFileSync } from "node:fs";
import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";
import { ALICE, BOB, STATS_TOKEN, STUN_SERVERS } from "./test/keys.ts";

const fixture = JSON.parse(readFileSync(new URL("./test/fixtures/handshake.json", import.meta.url), "utf8")) as {
  clientPublic: string;
};

// Keys the stand-in admission controller allows.
const allowed = new Set([ALICE.nodekey, BOB.nodekey, `nodekey:${fixture.clientPublic}`]);

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: { STATS_TOKEN, STUN_SERVERS },
        serviceBindings: {
          ADMISSION: async (req: Request) => {
            const body = await req.json<{ NodePublic?: string }>();
            return Response.json({ Allow: allowed.has(body.NodePublic ?? "") });
          },
        },
      },
    }),
  ],
  test: {
    include: ["test/**/*.test.ts"],
  },
});
