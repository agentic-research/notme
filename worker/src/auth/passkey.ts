// WebAuthn/passkey registration + authentication for auth.notme.bot.
//
// Uses @simplewebauthn/server (CF Workers compatible).
// Credentials stored in SigningAuthority DO SQLite.
// First registered passkey becomes admin — no manual config.

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";

import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from "@simplewebauthn/server";

const RP_NAME = "notme";
// RP ID is set per-request from the hostname (auth.notme.bot or self-hosted)

// ── DO SQLite schema for passkeys ──

export function ensurePasskeySchema(sql: {
  exec: (query: string, ...params: unknown[]) => { toArray: () => unknown[] };
}): void {
  // Principal model — passkey_users replaced by principals + capability_grants
  // (created by principals.ts ensurePrincipalSchema)
  // Keep passkey_users for backward compat migration
  sql.exec(`
    CREATE TABLE IF NOT EXISTS passkey_users (
      user_id      TEXT PRIMARY KEY,
      display_name TEXT,
      is_admin     INTEGER NOT NULL DEFAULT 0,
      created_at   TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
  sql.exec(`
    CREATE TABLE IF NOT EXISTS passkey_credentials (
      credential_id TEXT PRIMARY KEY,
      user_id       TEXT NOT NULL,
      public_key    TEXT NOT NULL,
      counter       INTEGER NOT NULL DEFAULT 0,
      transports    TEXT,
      created_at    TEXT NOT NULL DEFAULT (datetime('now')),
      last_used_at  TEXT
    )
  `);
  sql.exec(`
    CREATE TABLE IF NOT EXISTS passkey_challenges (
      challenge  TEXT PRIMARY KEY,
      user_id    TEXT,
      type       TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
}

// ── Registration ──

export async function registrationOptions(
  userId: string,
  displayName: string,
  rpId: string,
  sql: any,
): Promise<any> {
  ensurePasskeySchema(sql);
  sweepExpiredChallenges(sql);

  // Check if any users exist (first user = admin, no auth needed)
  const users = sql
    .exec("SELECT COUNT(*) as count FROM passkey_users")
    .toArray() as Array<{ count: number }>;
  const isFirstUser = (users[0]?.count ?? 0) === 0;

  // Get existing credentials for this user (for excludeCredentials)
  const existing = sql
    .exec(
      "SELECT credential_id, transports FROM passkey_credentials WHERE user_id = ?",
      userId,
    )
    .toArray() as Array<{ credential_id: string; transports: string | null }>;

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: rpId,
    userName: displayName,
    userID: (() => { const e = new TextEncoder().encode(userId); const b = new Uint8Array(e.length); b.set(e); return b; })(),
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },
    excludeCredentials: existing.map((c) => ({
      id: c.credential_id,
      transports: c.transports ? JSON.parse(c.transports) : undefined,
    })),
  });

  // Store challenge for verification
  sql.exec(
    "INSERT OR REPLACE INTO passkey_challenges (challenge, user_id, type) VALUES (?, ?, 'registration')",
    options.challenge,
    userId,
  );

  return { options, isFirstUser };
}

export async function verifyRegistration(
  userId: string,
  displayName: string,
  response: RegistrationResponseJSON,
  rpId: string,
  origin: string,
  sql: any,
): Promise<{ verified: boolean; isAdmin: boolean }> {
  ensurePasskeySchema(sql);

  // Get stored challenge
  const challenges = sql
    .exec(
      "SELECT challenge FROM passkey_challenges WHERE user_id = ? AND type = 'registration'",
      userId,
    )
    .toArray() as Array<{ challenge: string }>;

  if (challenges.length === 0) {
    throw new Error("no pending registration challenge");
  }

  const expectedChallenge = challenges[0]!.challenge;

  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge,
    expectedOrigin: origin,
    expectedRPID: rpId,
  });

  if (!verification.verified || !verification.registrationInfo) {
    return { verified: false, isAdmin: false };
  }

  const { credential } = verification.registrationInfo;

  // Check if first user (auto-admin)
  const users = sql
    .exec("SELECT COUNT(*) as count FROM passkey_users")
    .toArray() as Array<{ count: number }>;
  const isFirstUser = (users[0]?.count ?? 0) === 0;

  // Store user
  sql.exec(
    "INSERT OR IGNORE INTO passkey_users (user_id, display_name, is_admin) VALUES (?, ?, ?)",
    userId,
    displayName,
    isFirstUser ? 1 : 0,
  );

  // Store credential — base64 encode public key for SQLite TEXT column
  const pubKeyB64 = btoa(
    String.fromCharCode(...new Uint8Array(credential.publicKey)),
  );
  sql.exec(
    "INSERT INTO passkey_credentials (credential_id, user_id, public_key, counter, transports) VALUES (?, ?, ?, ?, ?)",
    credential.id,
    userId,
    pubKeyB64,
    credential.counter,
    JSON.stringify(response.response.transports ?? []),
  );

  // Clean up challenge
  sql.exec(
    "DELETE FROM passkey_challenges WHERE user_id = ? AND type = 'registration'",
    userId,
  );

  return { verified: true, isAdmin: isFirstUser };
}

// ── Authentication ──

// Decode the challenge value from the assertion's clientDataJSON. WebAuthn
// embeds the original challenge there (base64url-encoded JSON); we use it as
// a per-flow session identifier to look up the issued challenge by exact
// value rather than relying on "most recent insert" ordering.
function decodeChallengeFromClientData(
  clientDataJSONb64: string,
): string | null {
  try {
    let b64 = clientDataJSONb64.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    const parsed = JSON.parse(atob(b64)) as { challenge?: unknown };
    return typeof parsed.challenge === "string" ? parsed.challenge : null;
  } catch {
    return null;
  }
}

// Sweep expired challenge rows so the table doesn't grow unbounded.
// Lookup at verify time already filters with `created_at > datetime('now',
// '-5 minutes')`, so anything past that window is dead weight. We delete
// rows older than 1 hour — defense in depth: clients have well past the
// 5-minute window to complete, abandoned flows still get cleaned up, and
// the absolute cap doesn't depend on a separate scheduled job. Called from
// every options/verify entry point so the cleanup amortizes against real
// auth traffic. (notme-ae81c9 / M2 from session code review.)
const SWEEP_EXPIRED_CHALLENGES_SQL =
  "DELETE FROM passkey_challenges WHERE created_at < datetime('now', '-1 hour')";

function sweepExpiredChallenges(sql: any): void {
  sql.exec(SWEEP_EXPIRED_CHALLENGES_SQL);
}

export async function authenticationOptions(
  rpId: string,
  sql: any,
): Promise<any> {
  ensurePasskeySchema(sql);
  sweepExpiredChallenges(sql);

  const options = await generateAuthenticationOptions({
    rpID: rpId,
    userVerification: "preferred",
  });

  // Store challenge
  sql.exec(
    "INSERT OR REPLACE INTO passkey_challenges (challenge, type) VALUES (?, 'authentication')",
    options.challenge,
  );

  return options;
}

export async function verifyAuthentication(
  response: AuthenticationResponseJSON,
  rpId: string,
  origin: string,
  sql: any,
): Promise<{
  verified: boolean;
  userId: string | null;
  isAdmin: boolean;
}> {
  ensurePasskeySchema(sql);

  // Look up the issued challenge by the value the client submitted in
  // clientDataJSON. Challenges are unique random nonces, so this binds the
  // verification to THIS auth flow instead of picking "most recent". Without
  // this, two concurrent flows stomp each other's challenge (DoS) and the
  // server has no proof it actually issued the challenge it's verifying.
  // The 5-minute TTL filter enforces freshness.
  const submittedChallenge = decodeChallengeFromClientData(
    response.response.clientDataJSON,
  );
  if (!submittedChallenge) {
    return { verified: false, userId: null, isAdmin: false };
  }

  const challenges = sql
    .exec(
      "SELECT challenge FROM passkey_challenges WHERE challenge = ? AND type = 'authentication' AND created_at > datetime('now', '-5 minutes')",
      submittedChallenge,
    )
    .toArray() as Array<{ challenge: string }>;

  if (challenges.length === 0) {
    return { verified: false, userId: null, isAdmin: false };
  }

  const expectedChallenge = challenges[0]!.challenge;

  // Find credential
  const creds = sql
    .exec(
      "SELECT credential_id, user_id, public_key, counter FROM passkey_credentials WHERE credential_id = ?",
      response.id,
    )
    .toArray() as Array<{
    credential_id: string;
    user_id: string;
    public_key: string;
    counter: number;
  }>;

  if (creds.length === 0) {
    // Don't log credential IDs — leaks registered credential list to worker logs
    return { verified: false, userId: null, isAdmin: false };
  }

  const cred = creds[0]!;
  const pubKeyBytes = Uint8Array.from(atob(cred.public_key), (c) =>
    c.charCodeAt(0),
  );

  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge,
    expectedOrigin: origin,
    expectedRPID: rpId,
    credential: {
      id: cred.credential_id,
      publicKey: pubKeyBytes,
      counter: cred.counter,
    },
  });

  if (!verification.verified) {
    console.error("[passkey] verification returned false (no throw)");
    return { verified: false, userId: null, isAdmin: false };
  }

  // Update counter + last_used_at
  sql.exec(
    "UPDATE passkey_credentials SET counter = ?, last_used_at = datetime('now') WHERE credential_id = ?",
    verification.authenticationInfo.newCounter,
    cred.credential_id,
  );

  // Clean up challenge
  sql.exec(
    "DELETE FROM passkey_challenges WHERE challenge = ?",
    expectedChallenge,
  );

  // Check admin status
  const userRows = sql
    .exec(
      "SELECT is_admin FROM passkey_users WHERE user_id = ?",
      cred.user_id,
    )
    .toArray() as Array<{ is_admin: number }>;

  return {
    verified: true,
    userId: cred.user_id,
    isAdmin: (userRows[0]?.is_admin ?? 0) === 1,
  };
}
