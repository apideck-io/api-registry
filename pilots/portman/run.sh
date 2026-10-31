#!/usr/bin/env bash
# Contract-test a spec against the live API through the Apideck Proxy.
#
#   APIDECK_API_KEY=... APIDECK_APP_ID=... APIDECK_CONSUMER_ID=... \
#     pilots/portman/run.sh pilots/portman/hubspot-companies v2.validated.yaml hubspot https://api.hubapi.com
#
# Portman turns the spec plus portman-config.json into a Postman collection with contract and variation
# tests; Newman runs it. A collection pre-request script rewrites every request to the proxy, so the
# customer's credentials stay in Vault. Run reads only, against connections you own.
#   Set KEEP_COLLECTION=1 to copy the generated collection to <dir>/portman-collection.<spec>.json.
set -euo pipefail
dir=$1 spec=$2 service=$3 base=$4
# Portman's faker dependency is ESM-only; loading it needs Node 22's require(esm).
node -e 'const [a,b]=process.versions.node.split(".").map(Number); process.exit(a>22||(a===22&&b>=12)?0:1)' \
  || { echo "Node 22.12+ required (found $(node -v))" >&2; exit 1; }
# Read-only by construction: refuse a spec with any operation that isn't a GET, since the run calls the
# live connection and a write would change real data.
node -e '
const fs = require("fs"); const t = fs.readFileSync(process.argv[1], "utf8");
let yaml;
if (!t.trim().startsWith("{")) {
  try {
    yaml = require(require.resolve("yaml", { paths: [process.argv[2], process.cwd()] }));
  } catch {
    console.error("The yaml package is missing: run `npm ci` in the api-registry checkout first.");
    process.exit(1);
  }
}
const doc = yaml ? yaml.parse(t) : JSON.parse(t);
const writes = Object.entries(doc.paths ?? {}).flatMap(([p, item]) => ["put", "post", "patch", "delete"].filter((m) => item?.[m]).map((m) => `${m.toUpperCase()} ${p}`));
if (writes.length) { console.error(`Refusing: the spec has write operations (${writes.slice(0, 3).join(", ")}…). This runner is read-only.`); process.exit(1); }
' "$dir/$spec" "$(cd "$(dirname "$0")/../.." && pwd)" || exit 1
for v in APIDECK_API_KEY APIDECK_APP_ID APIDECK_CONSUMER_ID; do
  [ -n "${!v:-}" ] || { echo "$v is not set" >&2; exit 1; }
done
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
node -e '
const v = (key, value) => ({ key, value, enabled: true });
require("fs").writeFileSync(process.argv[1], JSON.stringify({ name: "proxy", values: [
  v("apideckApiKey", process.env.APIDECK_API_KEY), v("apideckAppId", process.env.APIDECK_APP_ID),
  v("apideckConsumerId", process.env.APIDECK_CONSUMER_ID), v("serviceId", process.argv[2]) ] }));
' "$work/env.json" "$service"
if ! npx -y @apideck/portman@1.35.2 -l "$dir/$spec" -c "$dir/portman-config.json" -b "$base" \
  -o "$work/collection.json" --syncPostman false --includeTests true > "$work/portman.log" 2>&1; then
  cat "$work/portman.log" >&2 # Portman reports most errors on stdout; show them before the temp dir goes
  exit 1
fi
if [ "${KEEP_COLLECTION:-}" = 1 ]; then cp "$work/collection.json" "$dir/portman-collection.${spec%.*}.json"; fi
# Portman's --runNewman does not pass the environment to the pre-request script; run Newman directly.
npx -y newman@6.2.3 run "$work/collection.json" -e "$work/env.json" --reporters cli
