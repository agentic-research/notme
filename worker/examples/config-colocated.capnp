# config-colocated.capnp — Co-located notme + agent Workers (009)
#
# One workerd process, two Workers, V8 isolate separation.
# The agent Worker has NO internet access — only a service binding to notme.
#
# Usage:
#   cd worker && npm run build:local
#   npx workerd serve examples/config-colocated.capnp --experimental
#
# Then:
#   curl http://localhost:3000/health         → agent health check
#   curl http://localhost:3000/try-fetch      → proves fetch() is blocked
#   curl http://localhost:8788/.well-known/jwks.json  → notme authority API

using Workerd = import "/workerd/workerd.capnp";

const config :Workerd.Config = (
  services = [
    # ── notme identity service (has internet access, holds keys) ──
    ( name = "notme",
      worker = .notmeWorker,
    ),

    # ── Agent Worker (network-isolated, talks to notme via service binding) ──
    ( name = "agent",
      worker = .agentWorker,
    ),

    # ── Internet access (only notme can use this) ──
    ( name = "internet",
      network = (
        allow = ["public"],
      ),
    ),

    # ── DO storage ──
    ( name = "do-storage",
      disk = (
        path = "/tmp/notme-colocated",
        writable = true,
      ),
    ),
  ],

  sockets = [
    # notme authority API (cert issuance, JWKS, discovery)
    ( name = "notme-http",
      address = "*:8788",
      http = (),
      service = "notme",
    ),
    # Agent API (proxied requests, signing, health)
    ( name = "agent-http",
      address = "localhost:3000",
      http = (),
      service = "agent",
    ),
  ],
);

# ── notme Worker: full identity authority ──
const notmeWorker :Workerd.Worker = (
  compatibilityDate = "2026-10-19",
  # No compatibilityFlags: from 2026-08-04 the date enables nodejs_compat
  # (and _v2), and workerd REFUSES to start with the redundant flag listed
  # (notme-430ad1). Node.js compat is still on, as it always was here.

  modules = [
    ( name = "worker",
      esModule = embed "../dist/worker.js",
    ),
  ],

  bindings = [
    ( name = "SITE_URL",
      text = "http://localhost:8788",
    ),
    ( name = "SIGNET_AUTHORITY_URL",
      text = "http://localhost:8788",
    ),
    ( name = "GHA_ALLOWED_OWNERS",
      text = "agentic-research",
    ),
    ( name = "NOTME_KEY_STORAGE",
      text = "ephemeral",
    ),

    ( name = "SIGNING_AUTHORITY",
      durableObjectNamespace = "SigningAuthority",
    ),
    ( name = "REVOCATION",
      durableObjectNamespace = "RevocationAuthority",
    ),
  ],

  durableObjectNamespaces = [
    ( className = "SigningAuthority",
      uniqueKey = "signing-authority-colocated",
      enableSql = true,
    ),
    ( className = "RevocationAuthority",
      uniqueKey = "revocation-authority-colocated",
      enableSql = true,
    ),
  ],

  durableObjectStorage = (localDisk = "do-storage"),
  globalOutbound = "internet",  # notme CAN reach the internet
);

# ── Agent Worker: network-isolated, service binding only ──
const agentWorker :Workerd.Worker = (
  # From 2026-08-04 this date turns Node.js compat on for the agent too. It
  # gives the agent no new reach: node:net/node:http still go through
  # globalOutbound, which it does not have (notme-430ad1).
  compatibilityDate = "2026-10-19",

  modules = [
    ( name = "agent",
      esModule = embed "agent-worker.js",
    ),
  ],

  bindings = [
    # The ONLY way the agent can interact with the outside world.
    #
    # `props` names THIS agent to notme, and every agent's NOTME binding
    # must set distinct props (notme-153f03, review M1). authChallenge() is
    # rate limited per binding props (10 / 60 s), so a binding with its own
    # props has its own budget. Bindings WITHOUT props are limited per
    # claimed identity plus one cap they all share, so one props-less agent
    # can still crowd out its props-less peers. Give a second agent Worker
    # its own value, e.g. "{\"agent\":\"reviewer\"}".
    ( name = "NOTME",
      service = (
        name = "notme",
        entrypoint = "AuthService",
        props = (json = "{\"agent\":\"example-agent\"}"),
      ),
    ),
  ],

  # NO globalOutbound — agent's fetch() is disabled
  # NO durableObjectStorage — agent has no persistent state
  # NO disk bindings — agent cannot read/write files
);
