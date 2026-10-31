#!/usr/bin/env bash
# Contract-test a spec against the live API through the Apideck Proxy.
#
#   APIDECK_API_KEY=... APIDECK_APP_ID=... APIDECK_CONSUMER_ID=... \
#     pilots/portman/run.sh pilots/portman/hubspot-companies v2.validated.yaml hubspot https://api.hubapi.com
#
# Portman turns the spec plus portman-config.json into a Postman collection with contract and variation
# tests; Newman runs it. A collection pre-request script rewrites every request to the proxy, so the
# customer's credentials stay in Vault. Run reads only, against connections you own.
set -euo pipefail
dir=$1 spec=$2 service=$3 base=$4
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
node -e '
const v = (key, value) => ({ key, value, enabled: true });
require("fs").writeFileSync(process.argv[1], JSON.stringify({ name: "proxy", values: [
  v("apideckApiKey", process.env.APIDECK_API_KEY), v("apideckAppId", process.env.APIDECK_APP_ID),
  v("apideckConsumerId", process.env.APIDECK_CONSUMER_ID), v("serviceId", process.argv[2]) ] }));
' "$work/env.json" "$service"
npx -y @apideck/portman -l "$dir/$spec" -c "$dir/portman-config.json" -b "$base" \
  -o "$work/collection.json" --syncPostman false --includeTests true > "$work/portman.log"
# Portman's --runNewman does not pass the environment to the pre-request script; run Newman directly.
npx -y newman@6 run "$work/collection.json" -e "$work/env.json" --reporters cli
