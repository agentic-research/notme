# shellcheck shell=bash
# selectors.sh — refuse release selectors that came from the operator's shell
# rather than the task command line (security review M6).
#
# Task exposes every exported environment variable as a template variable, so
# `{{.ENV}}` is satisfied by an `export ENV=production` left over from an
# earlier session — which silently undoes "no environment is reachable by
# omission". The tasks therefore pass their selectors to the scripts as
# ARGUMENTS (never through a Task `env:` block, which an exported variable of
# the same name also overrides), and the scripts compare each argument with
# the exported variable of the same name. Equal and non-empty means the value
# most likely came from the shell, so it is refused.
#
# The one false positive is typing the same value you also exported. The fix
# is the same either way: `unset NAME`.

# refuse_exported NAME VALUE
refuse_exported() {
  local name="$1" value="$2" exported
  exported="$(printenv "$name" 2>/dev/null || true)"
  if [ -n "$value" ] && [ -n "$exported" ] && [ "$value" = "$exported" ]; then
    echo "✗ $name='$value' is exported in your shell, and that is where this value came from." >&2
    echo "  Release selectors must be typed on the task command line. Run: unset $name" >&2
    exit 1
  fi
}
