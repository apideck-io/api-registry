# API registry

Machine-readable API specifications for the apps [Apideck](https://www.apideck.com) connects to, and for widely used apps it doesn't connect yet: OpenAPI, Swagger, Google Discovery, AsyncAPI, OData, XSD, GraphQL and Postman. One entry per app, each spec verified every night.

The registry stores **links, not copies**. Most vendor specs carry licences that don't allow redistribution, so an entry points at the vendor's own published file. The only specs stored here are ones authored in this repo.

## Layout

```
connectors/<id>.yaml   one entry per app (hand-maintained)
index.json             what the last check found per spec (generated: never edit)
specs/                 specs authored here: a few full ones, and auth-only specs (specs/<id>/auth.yaml)
overlays/              fixes to vendor specs, as OpenAPI Overlay documents
derived/graphql/       GraphQL SDL specs as introspection results (generated: never edit)
scripts/verify.mjs     validates entries, checks every spec it can reach, writes index.json
```

An entry:

```yaml
id: xero                      # Apideck connector id, kebab-case, equal to the file name
                              # (an app Apideck doesn't connect yet: its common slug, plus apideck: false)
name: "Xero"
specs:
  - name: "Xero Accounting API"
    url: "https://raw.githubusercontent.com/XeroAPI/Xero-OpenAPI/master/xero_accounting.yaml"
    format: openapi-3.0       # openapi-3.0 | openapi-3.1 (also 3.2) | swagger-2.0 | google-discovery | asyncapi-2 | postman-2.0 | postman-2.1 | odata-edmx | xsd | graphql
    provenance: vendor        # vendor | third-party | community | fork
    server: "https://api.xero.com/api.xro/2.0"
    license: "MIT"            # optional; as the vendor states it
    notes: "..."              # optional
```

Two optional fields cover vendors that don't serve a plain file:
- `extract` says how the verifier gets the spec when the URL doesn't serve a plain file: it unwraps a wrapper, or for `graphql-introspection` it queries the endpoint:
  - `zip-bundle`: a zip of module files (Zoho Books)
  - `markdown-json-fence`: JSON inside a Markdown code fence (Sage); when a page holds several OpenAPI documents, they are merged (Adyntel) if they agree on version, servers and security and no path, method or component is defined two different ways; otherwise the spec fails
  - `redoc-state`: embedded in a Redoc page's `__redoc_state` (Fortnox), or in the `redocStoreStr` field of a Redocly portal's page data (Drata)
  - `swagger-ui-init`: embedded as `swaggerDoc` in a swagger-ui-express init script (Minox)
  - `graphql-introspection`: no SDL file, but the endpoint answers an anonymous introspection query (Wave, Access Financials)
- `manual: login | bot-protection` records a spec CI can't fetch (it needs `notes` on how to get it).

The registry also covers widely used apps Apideck doesn't connect yet, so there's one place to find any app's spec. Those entries carry `apideck: false`; everything else about them is the same.

An app whose vendor publishes no spec still gets an entry with `specs: []` and a `notes` line saying what exists instead. That records that we looked.

`index.json` records, per spec:
- `status`: `ok`; `manual: login` or `manual: bot-protection` for specs CI can't fetch (recorded, never fetched); otherwise why it failed. A response without the format's identifying root, such as a JSON error payload, counts as a failure.
- `sha256`
- `bytes`
- `operations`, which counts differently per format:
  - OpenAPI and Swagger: path × method (including Azure's `x-ms-paths`, and OpenAPI 3.2's `query` method and `additionalOperations`)
  - Discovery: methods
  - AsyncAPI: publish and subscribe operations
  - Postman: requests
  - OData: entity sets
  - XSD: `…Rq` request elements
  - GraphQL: fields on the root `Query` and `Mutation` types
  - A zip bundle sums its files and adds `files`.
- `title`, `apiVersion`, `specVersion` and `server`
- `changedOn`: the last date the file's hash changed. A parameter `default` holding an ISO timestamp is left out of the hash, since some vendors render the current date into their spec on every request
- `formatMismatch`: set when the entry's `format` disagrees with the spec's own version (OpenAPI, Swagger, and a Postman collection's `info.schema`)
- `specIssues`: set when an OpenAPI or Swagger file's `info.title` or `info.version` is missing, empty, blank (whitespace only) or not a string (in a JSON file, such as `"version": 1`; YAML values are read as text, so a YAML `version: 1` passes); the spec is still indexed
- `fetchSha256`: the hash of the exact bytes served at the spec's URL, before any unwrapping. A consumer that downloads the URL compares its own bytes with this, so it uses the file this check saw. It is left out for extracted specs (`extract`: the page around the spec carries build hashes, so `sha256`, of the extracted spec, is what to compare) and where the bytes differ between requests and `sha256` is of a normalised form instead: Google Discovery documents (key-sorted, without `etag` and `revision`, generated date defaults replaced), zip bundles (their spec files' names and contents) and specs with generated date defaults (parsed, key-sorted, dates replaced). A consumer checks those against `sha256` with the same normalisation. GraphQL introspection answers aren't recorded: they come from the vendor's live endpoint.
- `suspicious` and `suspiciousSha`: up to three samples of text that reads like instructions to an AI or hides itself with bidirectional overrides, and a fingerprint of every such text (GraphQL descriptions included); a changed fingerprint holds the nightly PR
- `surface`: a short fingerprint of where calls go and how they authenticate (servers, host, security schemes and requirements); `surfaceChangedOn` is the last date it changed

## Integrity

`index.json` is what consumers trust, so a change to it goes through a pull request:

- Any change to a spec shows as Δ in the nightly PR with its new hash. `formatMismatch` and `specIssues` show as ⚠ too, without holding the PR.
- A change of servers or authentication, or a spec whose servers and authentication are checked for the first time (`⚠ surface`), text in a description or summary that reads like instructions to an AI agent or hides itself with bidirectional overrides or invisible Unicode tag characters, when it differs from what an earlier merge already accepted (`⚠ text`), or a spec that stopped resolving (✗ … newly failing; one already failing is listed without holding the PR) labels the PR `needs-review` and lists why at the top. The patterns are in `scripts/spec-safety.mjs`.
- Otherwise the PR is labelled `spec-drift`. It merges itself only when the repository variable `NIGHTLY_AUTOMERGE` is `true`; by default a person merges every nightly PR.

A consumer should pin a registry commit, download each spec, and refuse one that doesn't match: its bytes against `fetchSha256` where recorded, otherwise its normalised form against `sha256`.


## GraphQL schemas

A GraphQL spec is either an SDL file (Linear, Monday) or an endpoint that answers introspection (`extract: graphql-introspection`: Shopify, Wave). So consumers read one format, the nightly check parses every SDL spec with [graphql-js](https://github.com/graphql/graphql-js) and publishes it as an introspection result under `derived/graphql/`, named by a hash of the spec's URL, so connectors sharing a schema share the file. `index.json` records it per spec as `derived: { file, sha256, bytes }`, and the operation count comes from that parse. If graphql-js can't parse a vendor's SDL, the fields are counted as before, `derivedError` says why, and `derived` keeps pointing at the last result that did parse: it may be older than the spec now hashed, so check `derivedError` before relying on it. A full nightly run removes generated files no spec points at any more. The vendor's own file is still what `sha256` hashes.

## Overlays

When a vendor's spec is wrong in a way that breaks clients, the fix goes in an [OpenAPI Overlay](https://spec.openapis.org/overlay/) under `overlays/`, not in a fork. The entry points at it:

```yaml
  - name: "Square"
    url: "https://raw.githubusercontent.com/square/connect-api-specification/master/api.json"
    format: openapi-3.0
    provenance: vendor
    overlay: overlays/square.yaml
```

```yaml
overlay: 1.0.0
info: { title: Square spec fixes, version: 1.0.0 }
extends: https://raw.githubusercontent.com/square/connect-api-specification/master/api.json
actions:
  - target: "$.paths['/v2/vendors/{vendor_id}'].put"
    description: UpdateVendor puts {vendor_id} in its path but declares no parameters.
    update:
      parameters:
        - { name: vendor_id, in: path, required: true, schema: { type: string } }
```

- Overlays fix what the spec says about the API: a missing parameter, a wrong server, a duplicate operationId. How one product wires a connector (which setting fills a variable, allowed hosts) stays in that product.
- Every action needs a `description` saying what the vendor's spec gets wrong. `extends`, when given, must be the spec's `url`. Overlays apply to OpenAPI and Swagger specs only.
- The nightly check applies each overlay to the fetched spec and records it in `index.json` (`overlay.file`, `sha256`, `actions`). Actions whose target no longer matches anything are listed under `overlay.unmatched` (the vendor moved it: update the target), and updates that no longer change anything under `overlay.redundant` (the vendor fixed it: drop the action). Both are flagged with ⚠ in the nightly pull request.
- The spec's own `sha256` is of the vendor's file, not the overlaid result, so drift still means the vendor changed something.

Applied with [openapi-format](https://github.com/thim81/openapi-format), which supports Overlay 1.0 and 1.1.

## Auth-only specs

Many apps document their authentication and an API host but publish no spec. For those, the registry holds an **auth-only** spec, written here: an OpenAPI 3.1 document with the API's server, its security schemes (an API key's header or query parameter, a bearer token, HTTP basic credentials, or OAuth authorization and token URLs with scopes where the vendor lists them) and **no endpoints**. It tells a client how to connect, not what it can call.

```yaml
  - name: "Uber API (authentication only)"
    path: specs/uber/auth.yaml
    format: openapi-3.1
    provenance: community
    coverage: auth-only
    notes: "Authentication only: no endpoints. Written from Uber's developer documentation."
```

- Every value comes from the vendor's own documentation, or its official SDK where the docs don't print it, and the spec cites the page for each (`x-sources`: one URL per value, including `tokenEndpointAuthMethod` and `pkce` when those are set).
- The spec sets `x-auth-only: true`, and its entry sets `coverage: auth-only`; validation rejects an entry that points at a marked file without declaring it, and a declared spec without the marker.
- `scopes` is an empty map when the vendor lists none on a public page.
- An API-key or HTTP (bearer, basic) scheme cites the page that documents it as `x-sources.auth`. Before it is added, a documented read-only endpoint must refuse a request without credentials (401 or 403); the spec records that request (a path relative to the server, with a query string where the endpoint needs one) as `x-checked-endpoint`. When the vendor wants a prefixed header value (`Authorization: Token <key>`), the apiKey scheme carries it as `x-value-template` (`Token {key}`).
- Before an auth-only spec is added, the vendor's docs site and API host are checked for a published spec at the usual locations (`/openapi.json`, `/swagger.json`, `/api-docs`…); one found there is linked instead. Its token endpoint must answer an invalid request with an OAuth error, and its authorization endpoint and API host must respond.
- Where the vendor's documentation or official SDK states it, the security scheme carries `x-token-endpoint-auth-method` (`client_secret_basic` or `client_secret_post`) and `x-pkce-required`. Where it doesn't, the field is left out rather than guessed.
- `index.json` records `coverage: auth-only`. Consumers that need operations should skip these specs. A spec marked auth-only that lists any endpoints fails validation.
- When the vendor publishes a real spec, it replaces the auth-only one.

## Provenance

| Value | Meaning |
|---|---|
| `vendor` | Published by the API's owner, on their domain or official GitHub org |
| `third-party` | Published by a company building on the API (for example a wrapper vendor) |
| `community` | Maintained by individuals or community catalogs; verify before relying on it |
| `fork` | A copy of a vendor or community spec with fixes, maintained by its forker |

## Checks

```bash
npm ci
npm run validate          # entries only, no network (runs on every PR)
npm run verify            # fetch every URL spec, read every stored one, skip manual ones; rewrite index.json
node scripts/verify.mjs --only xero
```

A nightly workflow runs `verify` and opens a pull request when any spec changed, moved or stopped resolving. A spec that fails keeps its last good hash and count, and the failure is recorded in `status`, so one outage doesn't erase history.

## Contributing

Add or fix `connectors/<id>.yaml` and open a pull request. Prefer the vendor's raw file URL, for example `raw.githubusercontent.com` rather than a GitHub page. Don't edit `index.json`; the nightly check owns it.
