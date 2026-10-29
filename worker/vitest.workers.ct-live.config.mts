import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";
import {
  baseMiniflare,
  CT_LIVE_SUITES,
  x509Dir,
} from "./vitest.workers.config.mts";

// Pool config for the END-TO-END acceptance against a REAL transparency log
// (notme-1b46a8, Task 6). Third config, on purpose:
//
//   - vitest.workers.config.mts      no CT_LOG at all ("no binding, no change")
//   - vitest.workers.ct.config.mts   CT_LOG -> an inline stub that signs SCTs
//   - this one                       CT_LOG -> a proxy to a real azul ct_worker
//
// It is NOT part of `task worker:check`: it needs a running log. Without
// CT_LOG_URL the suite skips with a message naming what to run (see
// ct/README.md, "End-to-end acceptance").
//
// CT_LOG_URL is the shard's base, e.g. http://localhost:8787/logs/notmedev.
// The proxy forwards to its ORIGIN; the shard path reaches the authority as
// CT_LOG_PATH, exactly as a deployed binding would carry it.
//
// The proxy can be pointed at a DEAD PORT (POST /__control {"up": false}) so
// the outage in step 2 is a real refused TCP connection out of the log
// client, not a canned 500. `up: true` points it back at the log. That is the
// only state it keeps; everything else is a byte-for-byte forward.
const LOG_URL = process.env.CT_LOG_URL ? new URL(process.env.CT_LOG_URL) : null;

// A port nothing listens on. Checked by the acceptance driver before it runs
// (ct/scripts/acceptance.sh); if something does, step 2 fails loudly rather
// than passing for the wrong reason.
export const DEAD_PORT = 1;

const CT_LOG_PROXY = /* js */ `
const LIVE = ${JSON.stringify(LOG_URL?.origin ?? "")};
const DEAD = "http://127.0.0.1:${DEAD_PORT}";
let up = true;
export default {
  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === "/__control") {
      up = (await req.json()).up === true;
      return Response.json({ up, target: up ? LIVE : DEAD });
    }
    const target = (up ? LIVE : DEAD) + url.pathname + url.search;
    return fetch(new Request(target, req));
  },
};
`;

export default defineConfig({
  resolve: { alias: { "@peculiar/x509": x509Dir } },
  plugins: [
    cloudflareTest({
      main: "./worker.ts",
      miniflare: {
        ...baseMiniflare,
        bindings: {
          ...baseMiniflare.bindings,
          ...(LOG_URL
            ? { CT_LOG_PATH: LOG_URL.pathname.replace(/\/$/, "") }
            : {}),
          // The pin (final review I1): the authority embeds only SCTs from
          // this log id whose signature verifies under this key.
          // ct/scripts/acceptance.sh reads both from the log's metadata.json.
          ...(process.env.CT_LOG_ID ? { CT_LOG_ID: process.env.CT_LOG_ID } : {}),
          ...(process.env.CT_LOG_KEY ? { CT_LOG_KEY: process.env.CT_LOG_KEY } : {}),
        },
        ...(LOG_URL
          ? {
              serviceBindings: { CT_LOG: "ct-log-proxy" },
              workers: [
                {
                  name: "ct-log-proxy",
                  modules: true,
                  script: CT_LOG_PROXY,
                  compatibilityDate: baseMiniflare.compatibilityDate,
                },
              ],
            }
          : {}),
      },
    }),
  ],
  test: {
    include: CT_LIVE_SUITES,
    // A real log sequences on an interval; give each step room.
    testTimeout: 120_000,
  },
});
