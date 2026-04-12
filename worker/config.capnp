# workerd.capnp — local notme identity authority
#
# Same code as auth.notme.bot, runs locally via workerd.
# No Cloudflare account needed.
#
# Usage:
#   cd worker && npm run build   # bundle worker.ts → dist/
#   npx workerd serve config.capnp --experimental
#   # → http://localhost:8787
#
# Or via Docker:
#   docker run -p 8787:8787 -v $PWD:/app notme:latest

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
