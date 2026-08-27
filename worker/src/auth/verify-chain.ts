/**
 * verify-chain.ts — X.509 path validation for the delegation chain (ADR-019).
 *
 * `verifyX509` (verify-proof.ts) is SINGLE-HOP by design and stays that way:
 * a lone certificate is valid only if the root itself signed it. This module
 * is the chain walker for certificates the MACHINE tier signs — and it exists
 * only because it can carry all three bounds at once:
 *
 *   AUTHORITY  — child scopes ⊆ parent scopes   (auth/scope-chain.ts)
 *   DEPTH      — pathLenConstraint, RFC 5280 §6.1.4, enforced per tier
 *   NAMESPACE  — child identity segment-prefix-extends the parent's
 *                (ADR-019 D5, decided 2026-08-27: RFC 3820's confinement
 *                rule on WIMSE URIs)
 *
 * A chain verifier that walks signatures without the bounds would accept a
 * machine tier naming identities it has no business naming — which is why
 * delegation-depth.do.test.ts pinned the single-hop boundary until this
 * shipped with all three.
 *
 * Check order per hop mirrors verifyX509's, for the same oracle reason:
 * validity dates, then SIGNATURE, then contents (epoch, scopes, names) —
 * contents are only meaningful once the cert is known to be ours.
 */
import {
  BasicConstraintsExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  SubjectAlternativeNameExtension,
  X509Certificate,
} from "@peculiar/x509";
import { OID_SCOPES } from "../cert-authority";
import { escalatedScopes, verifyScopeChain } from "./scope-chain";
import { certEpoch, type VerifiedIdentity } from "./verify-proof";

/**
 * Does `child` sit strictly inside `parent`'s identity subtree?
 *
 * Segment-prefix extension, STRICT: same scheme, same host, parent's path
 * segments an exact prefix of the child's, and the child at least one segment
 * longer — equality is refused because a task claiming to BE the machine is
 * impersonation, not delegation (RFC 3820 likewise requires appending a
 * component, never restating the issuer's name).
 *
 * Segments compare RAW — percent-encoded, never decoded. Decoding first is
 * how "%2F" becomes a separator and a name escapes its subtree; the mint
 * paths percent-encode per segment (correlation-key.ts states the rule), and
 * the verifier must compare in the same alphabet the signer wrote.
 */
export function identityExtends(parent: string, child: string): boolean {
  const p = splitIdentity(parent);
  const c = splitIdentity(child);
  if (!p || !c) return false;
  if (p.scheme !== c.scheme || p.host !== c.host) return false;
  if (c.segments.length <= p.segments.length) return false;
  if (c.segments.some((s) => s.length === 0)) return false;
  return p.segments.every((seg, i) => c.segments[i] === seg);
}

function splitIdentity(
  uri: string,
): { scheme: string; host: string; segments: string[] } | null {
  const m = /^([a-z][a-z0-9+.-]*):\/\/([^/]+)(\/.*)?$/i.exec(uri);
  if (!m) return null;
  const path = m[3] ?? "";
  const segments = path === "" ? [] : path.slice(1).split("/");
  return { scheme: m[1]!.toLowerCase(), host: m[2]!.toLowerCase(), segments };
}

/** The single URI SAN a notme-minted cert carries, or null. */
export function certIdentityUri(cert: X509Certificate): string | null {
  const san = cert.getExtension(SubjectAlternativeNameExtension);
  if (!san) return null;
  const uris = san.names.items.filter((n) => n.type === "url");
  if (uris.length !== 1) return null;
  return uris[0]!.value || null;
}

/**
 * Scopes DER-encoded at OID_SCOPES: SEQUENCE OF UTF8String, or null when the
 * extension is absent. Minimal parser for exactly what cert-authority writes;
 * anything malformed returns null rather than a partial list — a verifier
 * that half-reads a scope list under-reports authority silently.
 */
export function certScopes(cert: X509Certificate): string[] | null {
  const ext = cert.getExtension(OID_SCOPES);
  if (!ext) return null;
  const der = new Uint8Array(ext.value);
  const seq = readTlv(der, 0);
  if (!seq || seq.tag !== 0x30 || seq.end !== der.length) return null;
  const scopes: string[] = [];
  let at = seq.contentStart;
  while (at < seq.end) {
    const s = readTlv(der, at);
    if (!s || s.tag !== 0x0c) return null; // UTF8String
    scopes.push(new TextDecoder().decode(der.subarray(s.contentStart, s.end)));
    at = s.end;
  }
  return scopes;
}

function readTlv(
  der: Uint8Array,
  at: number,
): { tag: number; contentStart: number; end: number } | null {
  if (at + 2 > der.length) return null;
  const tag = der[at]!;
  let len = der[at + 1]!;
  let headerLen = 2;
  if (len & 0x80) {
    const lenBytes = len & 0x7f;
    if (lenBytes === 0 || lenBytes > 2 || at + 2 + lenBytes > der.length) return null;
    len = 0;
    for (let i = 0; i < lenBytes; i++) len = len * 256 + der[at + 2 + i]!;
    headerLen = 2 + lenBytes;
  }
  const contentStart = at + headerLen;
  const end = contentStart + len;
  if (end > der.length) return null;
  return { tag, contentStart, end };
}

export interface VerifiedChainIdentity extends VerifiedIdentity {
  /** The leaf's WIMSE identity URI — confined to its issuer's subtree. */
  identity: string;
  /** The leaf's scopes — verified ⊆ every tier above it. */
  scopes: string[];
  /** How many intermediate tiers the chain passed through (1 = machine→task). */
  depth: number;
}

/**
 * Verify a leaf through intermediate tiers to the trusted root.
 *
 * `intermediatePems` is ordered leaf-side first: `[issuing]` for the
 * two-hop chain, the general walk for deeper ones — though today the root's
 * pathlen=1 and the tier's pathlen=0 make one intermediate the only depth
 * that can verify, and that is the point of the budget.
 *
 * The root's own pathLenConstraint IS enforced here, deliberately stricter
 * than RFC 5280 §6.1.1 (which excludes the anchor from path processing):
 * this verifier exists for one authority whose root advertises its budget on
 * purpose, and delegation-depth.do.test.ts pins that the budget equals the
 * tiers the authority can mint.
 */
export async function verifyCertChain(
  leafPem: string,
  intermediatePems: string[],
  caCertPem: string,
  currentEpoch: number,
): Promise<VerifiedChainIdentity> {
  if (intermediatePems.length === 0) {
    throw new Error("no intermediates — use verifyX509 for root-signed certs");
  }
  const now = new Date();
  const leaf = new X509Certificate(leafPem);
  const intermediates = intermediatePems.map((p) => new X509Certificate(p));
  const root = new X509Certificate(caCertPem);

  // Leaf-side-first order: [leaf, i0, i1, ...], each signed by the next.
  const chain = [leaf, ...intermediates];

  // 1. Validity windows — date-only, interprets nothing.
  for (const cert of chain) {
    if (cert.notAfter < now) throw new Error("cert expired");
    if (cert.notBefore > now) throw new Error("cert not yet valid");
  }

  // 2. Signatures, leaf up to root — before any content is trusted.
  for (let i = 0; i < chain.length; i++) {
    const signer = i + 1 < chain.length ? chain[i + 1]! : root;
    const ok = await chain[i]!.verify({ publicKey: signer.publicKey });
    if (!ok) {
      throw new Error(
        i + 1 < chain.length
          ? "cert signature invalid — not signed by its stated tier"
          : "cert signature invalid — chain does not reach the trusted CA",
      );
    }
  }

  // 3. Tier shape. Every intermediate must be a CA with keyCertSign; the
  // leaf must NOT be one — tasks are terminal (ADR-019 D4), and a CA leaf
  // is a delegation nobody granted.
  const leafBc = leaf.getExtension(BasicConstraintsExtension);
  if (leafBc?.ca) throw new Error("leaf is a CA — tasks are terminal");
  for (const tier of intermediates) {
    const bc = tier.getExtension(BasicConstraintsExtension);
    if (!bc?.ca) throw new Error("intermediate is not a CA — cannot have issued anything");
    const ku = tier.getExtension(KeyUsagesExtension);
    if (!ku || !(ku.usages & KeyUsageFlags.keyCertSign)) {
      throw new Error("intermediate lacks keyCertSign — not a delegation tier");
    }
  }

  // 4. Depth — the rank function. Walking down from the root, each CA's
  // pathLenConstraint bounds how many further CAs may follow it. With the
  // budget spent at every level, chains terminate because ℕ has no infinite
  // descent (ADR-019 D4).
  const tiersTopDown = [...intermediates].reverse();
  let budget = root.getExtension(BasicConstraintsExtension)?.pathLength ?? 0;
  for (const tier of tiersTopDown) {
    if (budget < 1) throw new Error("pathlen exceeded — a tier sits deeper than its issuer allows");
    budget = Math.min(budget - 1, tier.getExtension(BasicConstraintsExtension)?.pathLength ?? 0);
  }

  // 5. Epoch — rotation revokes the whole generation, every tier included.
  for (const cert of chain) {
    const epoch = certEpoch(cert);
    if (epoch === null) throw new Error("cert carries no epoch — cannot be checked against rotation");
    if (epoch !== currentEpoch) {
      throw new Error(
        `cert epoch ${epoch} does not match authority epoch ${currentEpoch} — revoked by rotation`,
      );
    }
  }

  // 6. Authority bound — child scopes ⊆ parent scopes at EVERY hop. A tier
  // without a scope list cannot bound its children, so it is refused rather
  // than treated as unlimited (absence must never widen).
  for (let i = chain.length - 1; i > 0; i--) {
    const parentScopes = certScopes(chain[i]!);
    if (parentScopes === null) throw new Error("tier carries no scopes — cannot bound its children");
    const childScopes = certScopes(chain[i - 1]!) ?? [];
    if (!verifyScopeChain(parentScopes, childScopes)) {
      throw new Error(
        `scope escalation in chain: ${escalatedScopes(parentScopes, childScopes).join(", ")} not held by the issuing tier`,
      );
    }
  }

  // 7. Namespace bound — D5's rule, at EVERY hop below the top tier. The top
  // tier's own identity was bound at issuance by the authority's route; each
  // name below it must sit strictly inside its issuer's subtree.
  for (let i = chain.length - 1; i > 0; i--) {
    const parentId = certIdentityUri(chain[i]!);
    const childId = certIdentityUri(chain[i - 1]!);
    if (!parentId) throw new Error("tier carries no identity URI — cannot confine its children");
    if (!childId) throw new Error("cert carries no identity URI");
    if (!identityExtends(parentId, childId)) {
      throw new Error(
        "namespace escape: identity is outside the issuing tier's subtree (ADR-019 D5)",
      );
    }
  }

  const identity = certIdentityUri(leaf)!;
  return {
    type: "x509",
    issuer: root.subjectName.getField("CN")?.[0] ?? root.subject,
    subject: leaf.subjectName.getField("CN")?.[0] ?? leaf.subject,
    identity,
    scopes: certScopes(leaf) ?? [],
    depth: intermediates.length,
  };
}
