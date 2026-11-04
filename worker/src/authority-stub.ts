// authority-stub.ts — the SigningAuthority stub, TYPED (notme-32003c).
//
// The route handlers take `env: any`, so `env.SIGNING_AUTHORITY.get(...)` is
// an `any` stub: every argument type-checks, and a branded parameter such as
// mintBridgeCertPair's AuthMethod constrains nothing. Getting the stub here
// gives it the class's real RPC signatures, so passing an unchecked string as
// an authMethod is a compile error at the call site.
//
// Every route that mints should take its stub from here. `env: any` itself
// is the wider hole, and typing it is out of this bead's scope.

import type { SigningAuthority } from "./signing-authority";

export function authorityStub(
  env: { SIGNING_AUTHORITY: DurableObjectNamespace<SigningAuthority> },
  name = "default",
): DurableObjectStub<SigningAuthority> {
  return env.SIGNING_AUTHORITY.get(env.SIGNING_AUTHORITY.idFromName(name));
}
