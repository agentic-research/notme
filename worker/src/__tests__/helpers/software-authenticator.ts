/**
 * software-authenticator.ts — a REAL WebAuthn authenticator in software.
 *
 * Exists so tests can drive /auth/passkey/register/verify and /login/verify
 * end to end through @simplewebauthn/server's actual verification — not a
 * mock of it. It generates a P-256 credential, builds a genuine
 * attestationObject ("none" fmt, CBOR, authData carrying the COSE key), and
 * signs real assertions over authenticatorData || SHA-256(clientDataJSON).
 *
 * Anything this produces that the server accepts, a hardware key could have
 * produced. Anything it rejects, the server would reject from hardware too.
 */
const te = new TextEncoder();

/**
 * Minimal CANONICAL CBOR (RFC 8949 §4.2) — exactly the subset WebAuthn
 * needs: maps, text, byte strings, non-negative and negative ints.
 *
 * Not cbor-x: it wraps every Map in tag 259 and every byte array in tag 64,
 * which is valid CBOR and what no authenticator on earth emits. A verifier
 * that half-tolerates those tags produces confusing downstream failures
 * rather than a clean rejection, which is how this helper first mis-read
 * the challenge as "undefined".
 */
function cborEncode(v: unknown): Uint8Array {
  const out: number[] = [];
  const head = (major: number, n: number) => {
    if (n < 24) out.push((major << 5) | n);
    else if (n < 0x100) out.push((major << 5) | 24, n);
    else if (n < 0x10000) out.push((major << 5) | 25, n >> 8, n & 0xff);
    else out.push((major << 5) | 26, (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
  };
  const enc = (x: unknown) => {
    if (typeof x === "number") {
      if (x >= 0) head(0, x);
      else head(1, -1 - x);
    } else if (typeof x === "string") {
      const b = te.encode(x);
      head(3, b.length);
      out.push(...b);
    } else if (x instanceof Uint8Array) {
      head(2, x.length);
      out.push(...x);
    } else if (x instanceof Map) {
      head(5, x.size);
      for (const [k, val] of x) {
        enc(k);
        enc(val);
      }
    } else {
      throw new Error(`cbor: unsupported ${typeof x}`);
    }
  };
  enc(v);
  return new Uint8Array(out);
}

export function b64u(bytes: ArrayBuffer | Uint8Array): string {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return btoa(String.fromCharCode(...u8))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function sha256(data: Uint8Array | string): Promise<Uint8Array> {
  const bytes = typeof data === "string" ? te.encode(data) : data;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** DER ECDSA signature from WebCrypto's raw r||s. WebAuthn wants DER. */
function rawToDer(raw: Uint8Array): Uint8Array {
  const half = raw.length / 2;
  const int = (b: Uint8Array) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    let v = b.subarray(i);
    if (v[0]! & 0x80) v = concat(new Uint8Array([0]), v);
    return concat(new Uint8Array([0x02, v.length]), v);
  };
  const r = int(raw.subarray(0, half));
  const s = int(raw.subarray(half));
  return concat(new Uint8Array([0x30, r.length + s.length]), r, s);
}

export class SoftwareAuthenticator {
  #keys!: CryptoKeyPair;
  #credentialId = crypto.getRandomValues(new Uint8Array(16));
  #counter = 0;
  readonly rpId: string;
  readonly origin: string;

  constructor(rpId: string, origin: string) {
    this.rpId = rpId;
    this.origin = origin;
  }

  static async create(rpId: string, origin: string): Promise<SoftwareAuthenticator> {
    const a = new SoftwareAuthenticator(rpId, origin);
    a.#keys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    return a;
  }

  get credentialIdB64u(): string {
    return b64u(this.#credentialId);
  }

  async #cosePublicKey(): Promise<Uint8Array> {
    const jwk = (await crypto.subtle.exportKey("jwk", this.#keys.publicKey)) as JsonWebKey;
    const dec = (s: string) =>
      Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
    // COSE_Key: kty EC2(2), alg ES256(-7), crv P-256(1), x, y
    const m = new Map<number, unknown>([
      [1, 2], [3, -7], [-1, 1], [-2, dec(jwk.x!)], [-3, dec(jwk.y!)],
    ]);
    return cborEncode(m);
  }

  async #authData(flags: number, withCredential: boolean): Promise<Uint8Array> {
    const rpIdHash = await sha256(this.rpId);
    const counter = new Uint8Array(4);
    new DataView(counter.buffer).setUint32(0, this.#counter, false);
    if (!withCredential) return concat(rpIdHash, new Uint8Array([flags]), counter);
    const aaguid = new Uint8Array(16);
    const idLen = new Uint8Array(2);
    new DataView(idLen.buffer).setUint16(0, this.#credentialId.length, false);
    return concat(
      rpIdHash, new Uint8Array([flags]), counter,
      aaguid, idLen, this.#credentialId, await this.#cosePublicKey(),
    );
  }

  /** A RegistrationResponseJSON for the given server challenge. */
  async register(challenge: string) {
    const clientDataJSON = te.encode(JSON.stringify({
      type: "webauthn.create", challenge, origin: this.origin, crossOrigin: false,
    }));
    // flags: UP(0x01) | UV(0x04) | AT(0x40)
    const authData = await this.#authData(0x45, true);
    const attestationObject = cborEncode(
      new Map<string, unknown>([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]),
    );
    return {
      id: this.credentialIdB64u,
      rawId: this.credentialIdB64u,
      type: "public-key" as const,
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64u(clientDataJSON),
        attestationObject: b64u(attestationObject),
        transports: ["internal"],
      },
    };
  }

  /** An AuthenticationResponseJSON — a real signature over the real challenge. */
  async authenticate(challenge: string) {
    this.#counter += 1;
    const clientDataJSON = te.encode(JSON.stringify({
      type: "webauthn.get", challenge, origin: this.origin, crossOrigin: false,
    }));
    const authData = await this.#authData(0x05, false); // UP | UV
    const toSign = concat(authData, await sha256(clientDataJSON));
    const raw = new Uint8Array(
      await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, this.#keys.privateKey, toSign),
    );
    return {
      id: this.credentialIdB64u,
      rawId: this.credentialIdB64u,
      type: "public-key" as const,
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64u(clientDataJSON),
        authenticatorData: b64u(authData),
        signature: b64u(rawToDer(raw)),
      },
    };
  }
}
