import type { Platform } from "./platform";
import type { CABundle } from "./revocation";

const CURRENT_BUNDLE_CACHE_KEY = "bundle:current";

type SigningAuthorityStub = {
  generateBundle(): Promise<CABundle>;
};

type EnvWithSigningAuthority = {
  SIGNING_AUTHORITY: {
    idFromName(name: string): unknown;
    get(id: unknown): SigningAuthorityStub;
  };
};

export async function ensureCurrentCABundle(
  env: EnvWithSigningAuthority,
  platform: Platform,
): Promise<CABundle> {
  const existingBundle = await platform.cache.get(CURRENT_BUNDLE_CACHE_KEY);
  if (existingBundle) {
    try {
      return JSON.parse(existingBundle) as CABundle;
    } catch {
      // Regenerate below; a malformed cache entry should not pin the endpoint down.
    }
  }

  const authorityId = env.SIGNING_AUTHORITY.idFromName("default");
  const authority = env.SIGNING_AUTHORITY.get(authorityId);
  const bundle = await authority.generateBundle();
  await platform.cache.put(CURRENT_BUNDLE_CACHE_KEY, JSON.stringify(bundle));
  return bundle;
}

export async function handleInternalCABundle(
  request: Request,
  env: EnvWithSigningAuthority,
  platform: Platform,
): Promise<Response> {
  if (request.method !== "GET") {
    return Response.json({ error: "method not allowed" }, { status: 405 });
  }

  try {
    const bundle = await ensureCurrentCABundle(env, platform);
    return Response.json(bundle, {
      headers: { "Cache-Control": "no-store" },
    });
  } catch (e: any) {
    return Response.json(
      { error: `authority unavailable: ${e?.message ?? "unknown"}` },
      { status: 503 },
    );
  }
}
