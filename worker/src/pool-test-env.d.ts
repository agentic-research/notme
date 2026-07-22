// Type augmentation for the vitest-pool-workers `cloudflare:test` env, so the
// *.do.test.ts files type-check with the same bindings the pool config declares
// (vitest.workers.config.mts). `cloudflare:test` types `env` as `Cloudflare.Env`
// (workers-types 5), so we augment that interface. This file is a module (it
// imports SigningAuthority), so the augmentation must go through `declare
// global`. Loaded only by tsconfig.test.json — runtime bindings come from the pool.
import type { SigningAuthority } from "./signing-authority";

declare global {
  namespace Cloudflare {
    interface Env {
      // SigningAuthority extends DurableObject → RPC-branded, so the namespace
      // carries the concrete class. (runInDurableObject can't infer the instance
      // type through its stub in workers-types 5 — the callbacks cast it — but
      // typing the binding still documents which DO this is + types env.get.)
      SIGNING_AUTHORITY: DurableObjectNamespace<SigningAuthority>;
      // RevocationAuthority is a plain class (not `extends DurableObject`) → not
      // RPC-branded; the generic constraint rejects it, so use the base type,
      // matching RevocationEnv in revocation.ts.
      REVOCATION: DurableObjectNamespace;
      CA_BUNDLE_CACHE: KVNamespace;
    }
  }
}

export {};
