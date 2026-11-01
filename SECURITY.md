# Security

## Reporting a vulnerability

**Do not open a public issue or pull request.** Email **security@apideck.com** with a description, the
affected entry or file, and how to reproduce it. That includes a vendor spec you believe was tampered with,
or text in one that tries to instruct an AI agent.

## What the registry protects

The registry links to specs; it doesn't host them. A vendor (or whoever controls a spec's URL) can change a
file at any time, so the registry can't prevent a change. It makes sure a change is **seen, reviewed and
pinned** before anyone relies on it.

| Risk | What protects against it |
|---|---|
| A spec changes after review (the vendor, a compromised host, a hijacked GitHub raw URL) | `index.json` records each spec's hash: `fetchSha256` for the exact bytes, or `sha256` of a normalised form where the bytes vary per request (see the README). A consumer that pins a registry commit and refuses a spec whose hash doesn't match only ever uses a file the registry checked. |
| Calls are redirected, or credentials sent to another host | `surface` fingerprints each spec's servers, hosts and authentication (security schemes, OAuth URLs, Postman auth, variables and scripts). A change holds the nightly pull request for a person (`⚠ surface`). |
| Text in a spec tries to instruct an AI agent (prompt injection) | Descriptions, summaries and GraphQL descriptions are scanned for instruction-like phrases, chat-template tokens, bidirectional overrides and invisible Unicode tag characters (`scripts/spec-safety.mjs`). New or changed matches hold the nightly pull request (`⚠ text`). Consumers should still treat spec text as untrusted. |
| A malicious or careless change to the registry itself | Every change, including the nightly hash update, arrives as a pull request. The nightly PR merges itself only when nothing is flagged and the repository variable `NIGHTLY_AUTOMERGE` is `true` (off by default). |
| A spec stops resolving or starts failing | A newly failing spec (`✗ … newly failing`) holds the nightly pull request. |

## What a consumer should do

1. Pin a registry commit, not `master`.
2. Download each spec from its `url` and compare it with `fetchSha256` (or `sha256` with the README's
   normalisation). Refuse a mismatch; keep the previous version until the registry's next check.
3. Treat spec text (descriptions, summaries, examples) as untrusted input to any model.
4. Only call the hosts the spec's `server` and `surface` describe.

[openintegration](https://openintegration.vercel.app) does all four.

## Known limits

- Vendors don't sign their specs, so a hash proves "unchanged since the registry checked it", not "published
  by the vendor". Provenance (`vendor`, `community`…) is a reviewed claim, recorded per entry.
- The instruction-like text check is a pattern list. It catches common forms, not every possible one.
- A spec served from a GraphQL endpoint (`extract: graphql-introspection`) is the vendor's live API
  describing itself; it is hashed but can't be re-downloaded byte for byte.
