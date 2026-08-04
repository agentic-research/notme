# workerd.capnp — local notme identity authority
#
# Same code as auth.notme.bot, runs locally via workerd.
# No Cloudflare account needed.
#
# Usage:
#   cd worker && npm run build:local   # bundle worker.ts → dist/
#   npx workerd serve config.capnp --experimental
#   # → http://localhost:8788
#
# Or via Docker (versioned tags only — no `:latest` is published):
#   docker run -p 8788:8788 ghcr.io/agentic-research/notme:0.1.0

using Workerd = import "/workerd/workerd.capnp";

const config :Workerd.Config = (
  services = [
    # The notme identity authority Worker
    ( name = "notme",
      worker = .notmeWorker,
    ),

    # Internet access (for JWKS fetches, GitHub API calls)
    ( name = "internet",
      network = (
        allow = ["public"],
      ),
    ),


    # Local disk for DO SQLite storage
    ( name = "do-storage",
      disk = (
        path = "/data/do",
        writable = true,
      ),
    ),
  ],

  sockets = [
    ( name = "http",
      address = "*:8788",
      http = (),
      service = "notme",
    ),
  ],
);

const notmeWorker :Workerd.Worker = (
  compatibilityDate = "2026-03-01",
  compatibilityFlags = ["nodejs_compat"],

  modules = [
    ( name = "worker",
      esModule = embed "dist/worker.js",
    ),
  ],

  bindings = [
    # Environment variables
    ( name = "SITE_URL",
      text = "http://localhost:8788",
    ),
    ( name = "SIGNET_AUTHORITY_URL",
      text = "http://localhost:8788",
    ),
    ( name = "GHA_ALLOWED_OWNERS",
      text = "agentic-research",
    ),
    # Key storage mode — ephemeral for local dev (no private key on disk)
    ( name = "NOTME_KEY_STORAGE",
      text = "ephemeral",
    ),
    # Delegated JWT issuers (ADR-015). Local cloister serves on :8787 and its
    # `iss` is its request-derived base URL, so this is what unblocks a local
    # /oauth/token — without it signJwt answers ISSUER_NOT_DELEGATED for every
    # issuer and cloister 503s with everything else correct.
    #
    # Safe to commit BECAUSE it is localhost. This is an allowlist of who may
    # be issued a delegated key, not a secret: a caller who could register an
    # issuer could register https://auth.notme.bot, which is why it is operator
    # config rather than caller-supplied. Deployed values belong in wrangler
    # vars, and never in worker/.dev.vars — see the secrets block at the end of
    # .gitignore for why that file was the wrong place to reach for.
    ( name = "DELEGATED_JWT_ISSUERS",
      text = "http://localhost:8787",
    ),

    # Durable Object namespace bindings (must match env.SIGNING_AUTHORITY etc. in code)
    ( name = "SIGNING_AUTHORITY",
      durableObjectNamespace = "SigningAuthority",
    ),
    ( name = "REVOCATION",
      durableObjectNamespace = "RevocationAuthority",
    ),
  ],

  # DOs run locally via workerd SQLite — same API as CF edge
  durableObjectNamespaces = [
    ( className = "SigningAuthority",
      uniqueKey = "signing-authority-local",
      enableSql = true,
    ),
    ( className = "RevocationAuthority",
      uniqueKey = "revocation-authority-local",
      enableSql = true,
    ),
  ],

  durableObjectStorage = (localDisk = "do-storage"),
  # No cacheApiOutbound — Cache API not available locally.
  # worker.ts detects local mode and skips caches.default entirely.

  globalOutbound = "internet",
);
