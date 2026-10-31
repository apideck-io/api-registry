# Pilot: validating generated specs with Portman

Many vendors publish API docs but no machine-readable spec. This pilot tests one way to produce a spec we can trust anyway:

1. Generate a spec from the public docs.
2. Contract-test it against the live API with [Portman](https://github.com/apideck-libraries/portman).
3. Fix the spec from what the tests report.

HubSpot CRM Companies is the test case because HubSpot *does* publish an official spec, so the result can be scored against ground truth. Only read operations were run, on our own HubSpot connection, through the Apideck Proxy.

## Method

| Step | File | What changed |
|---|---|---|
| v0: generated from docs | `hubspot-companies/v0.generated.yaml` | Built only from developers.hubspot.com. The docs list the two GET paths and three query params, and give **no response shape and no pagination**. Everything else is inferred from REST conventions and marked `x-inferred`. |
| Contract run | `portman-config.json` | Status, content type, JSON body and schema validation on each operation. `assignVariables` chains list → get-by-id. Objects in the spec are closed (`additionalProperties: false`), so any undocumented field fails the test. |
| v1: fixed from the run | `v1.validated.yaml` | Adds `archived`, `url` and `paging.next.link`, which the strict schema reported as unexpected. |
| Variation run | `portman-config.json` (`variationTests`) | Re-runs the operations with `associations`, `propertiesWithHistory` and `archived=true`. Some fields only appear when a request asks for them. |
| v2: fixed from variations | `v2.validated.yaml` | Adds `associations`, `propertiesWithHistory` and `archivedAt`, and marks the fields seen in every response as required. All 12 assertions pass. |

## Result against HubSpot's official spec

These are the two GET operations, scored against `HubSpot/HubSpot-public-api-spec-collection` (CRM Companies v3).

| | Params (of 12) | Company fields (of 11) | Paging (of 2) | Required fields (of 5) | Fields that don't exist |
|---|---|---|---|---|---|
| v0, docs only | 10 | 4 | 1 | 2 | 0 |
| v1, after contract run | 10 | 6 | 2 | 2 | 0 |
| v2, after variations | 10 | 9 | 2 | 5 (plus `url`, which is optional) | 0 |

What contract testing can't find:
- **`objectWriteTraceId` and `warnings`** only appear on write responses, so a read-only run never sees them.
- **`archived` and `idProperty` on get-by-id** never appear in a response, so they're invisible from the outside. Only the docs or a request that fails can reveal a missing request parameter.
- **"Required"** is inferred from "present in every response we saw." That's right for 5 of 5 here, plus one field that's optional in the official spec.

## What this means for docs-only vendors

- A generated spec that has passed contract and variation tests on real responses is good enough to index read operations behind the proxy. Record it with provenance `generated` and say which operations were exercised.
- Write operations need a sandbox or test records. Don't contract-test writes against a customer's data.
- Coverage is limited by what the docs name. The tests correct shapes; they don't discover endpoints.

## Running it

```bash
APIDECK_API_KEY=… APIDECK_APP_ID=… APIDECK_CONSUMER_ID=… \
  pilots/portman/run.sh pilots/portman/hubspot-companies v2.validated.yaml hubspot https://api.hubapi.com
```

The connected account needs at least one company: get-by-id uses the first id from the list call, and with none it requests an unfilled `{{companyId}}` and fails with 404. Node 22.12+ is required, and Portman is pinned to 1.35.2, the version tested.

Requests go to `https://unify.apideck.com/proxy`, with the original URL in `x-apideck-downstream-url`, so Vault supplies the HubSpot token. Portman's own `--runNewman` doesn't pass the environment to the collection's pre-request script, so the script runs Newman directly.
