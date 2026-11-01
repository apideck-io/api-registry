# API registry

Machine-readable API specifications for the apps [Apideck](https://www.apideck.com) connects to: OpenAPI, Swagger, Google Discovery, AsyncAPI, OData, XSD, GraphQL and Postman. One entry per app, each spec verified every night.

The registry stores **links, not copies**. Most vendor specs carry licences that don't allow redistribution, so an entry points at the vendor's own published file. The only specs stored here are ones authored in this repo.

## Layout

```
connectors/<id>.yaml   one entry per app (hand-maintained)
index.json             what the last check found per spec (generated: never edit)
specs/                 the few specs authored here
overlays/              fixes to vendor specs, as OpenAPI Overlay documents
derived/graphql/       GraphQL SDL specs as introspection results (generated: never edit)
scripts/verify.mjs     validates entries, checks every spec it can reach, writes index.json
```

An entry:

```yaml
id: xero                      # Apideck connector id, kebab-case, equal to the file name
name: "Xero"
specs:
  - name: "Xero Accounting API"
    url: "https://raw.githubusercontent.com/XeroAPI/Xero-OpenAPI/master/xero_accounting.yaml"
    format: openapi-3.0       # openapi-3.0 | openapi-3.1 | swagger-2.0 | google-discovery | asyncapi-2 | postman-2.1 | odata-edmx | xsd | graphql
    provenance: vendor        # vendor | third-party | community | fork
    server: "https://api.xero.com/api.xro/2.0"
    license: "MIT"            # optional; as the vendor states it
    notes: "..."              # optional
```

Two optional fields cover vendors that don't serve a plain file:
- `extract` says how the verifier gets the spec when the URL doesn't serve a plain file: it unwraps a wrapper, or for `graphql-introspection` it queries the endpoint:
  - `zip-bundle`: a zip of module files (Zoho Books)
  - `markdown-json-fence`: JSON inside a Markdown code fence (Sage)
  - `redoc-state`: embedded in a Redoc page's `__redoc_state` (Fortnox)
  - `swagger-ui-init`: embedded as `swaggerDoc` in a swagger-ui-express init script (Minox)
  - `graphql-introspection`: no SDL file, but the endpoint answers an anonymous introspection query (Wave, Access Financials)
- `manual: login | bot-protection` records a spec CI can't fetch (it needs `notes` on how to get it).

An app whose vendor publishes no spec still gets an entry with `specs: []` and a `notes` line saying what exists instead. That records that we looked.

`index.json` records, per spec:
- `status`: `ok`; `manual: login` or `manual: bot-protection` for specs CI can't fetch (recorded, never fetched); otherwise why it failed. A response without the format's identifying root, such as a JSON error payload, counts as a failure.
- `sha256`
- `bytes`
- `operations`, which counts differently per format:
  - OpenAPI and Swagger: path × method
  - Discovery: methods
  - AsyncAPI: publish and subscribe operations
  - Postman: requests
  - OData: entity sets
  - XSD: `…Rq` request elements
  - GraphQL: fields on the root `Query` and `Mutation` types
  - A zip bundle sums its files and adds `files`.
- `title`, `apiVersion`, `specVersion` and `server`
- `changedOn`: the last date the file's hash changed

## GraphQL schemas

A GraphQL spec is either an SDL file (Linear, Monday) or an endpoint that answers introspection (`extract: graphql-introspection`: Shopify, Wave). So consumers read one format, the nightly check parses every SDL spec with [graphql-js](https://github.com/graphql/graphql-js) and publishes it as an introspection result under `derived/graphql/`, named by a hash of the spec's URL, so connectors sharing a schema share the file. `index.json` gives each spec's file name. `index.json` records it per spec as `derived: { file, sha256, bytes }`, and the operation count comes from that parse. If graphql-js can't parse a vendor's SDL, the fields are counted as before, `derivedError` says why, and `derived` keeps pointing at the last result that did parse: it may be older than the spec now hashed, so check `derivedError` before relying on it. A full nightly run removes generated files no spec points at any more. The vendor's own file is still what `sha256` hashes.

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
