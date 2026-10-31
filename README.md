# API registry

Machine-readable API specifications for the apps [Apideck](https://www.apideck.com) connects to: OpenAPI, Swagger, Google Discovery, AsyncAPI, OData, XSD, GraphQL and Postman. One entry per app, each spec verified every night.

The registry stores **links, not copies**. Most vendor specs carry licences that don't allow redistribution, so an entry points at the vendor's own published file. The only specs stored here are ones authored in this repo.

## Layout

```
connectors/<id>.yaml   one entry per app (hand-maintained)
index.json             what the last check found per spec (generated: never edit)
specs/                 the few specs authored here
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
