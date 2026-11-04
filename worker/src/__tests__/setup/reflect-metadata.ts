/**
 * reflect-metadata.ts — the Reflect polyfill @peculiar/x509 needs, loaded
 * before anything imports x509 (notme-3ee3b0).
 *
 * x509 2.0 dropped reflect-metadata from its own dependencies (PR #130): its
 * tsyringe container throws "tsyringe requires a reflect polyfill" when the
 * module is evaluated without one. Production loads it as worker.ts's first
 * import, but a test file imports x509 (or a module that does) directly,
 * never through worker.ts, so every pool lists this file FIRST in
 * setupFiles. Removing it fails every suite that touches a certificate.
 */
import "reflect-metadata";
