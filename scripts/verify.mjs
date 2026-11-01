// Validates every connectors/*.yaml entry and, unless --validate-only, fetches each spec and writes
// index.json: sha256, operation count, title, API version and fetch status per spec.
//
//   node scripts/verify.mjs [--validate-only] [--only <id>]
//
// index.json is generated; never edit it by hand. A spec that fails to fetch keeps its last good
// sha256 and operation count, with `status` recording the failure, so one outage doesn't erase history.

import { createHash } from "node:crypto";
import { inflateRawSync } from "node:zlib";
import { fileURLToPath } from "node:url";
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import openapiFormat from "openapi-format";

const { openapiOverlay, resolveJsonPathValue } = openapiFormat;

const ROOT = fileURLToPath(new URL("..", import.meta.url)); // decoded, so paths with spaces work
const args = process.argv.slice(2);
const VALIDATE_ONLY = args.includes("--validate-only");
const onlyEq = args.find((a) => a.startsWith("--only="));
const ONLY = onlyEq ? onlyEq.slice(7) : args.includes("--only") ? args[args.indexOf("--only") + 1] ?? "" : null;
if (ONLY === "" || ONLY?.startsWith("--")) {
  console.error("--only needs a connector id");
  process.exit(1);
}

const FORMATS = new Set(["openapi-3.0", "openapi-3.1", "swagger-2.0", "google-discovery", "asyncapi-2", "postman-2.1", "odata-edmx", "xsd", "graphql"]);
const PROVENANCE = new Set(["vendor", "third-party", "community", "fork"]);
const ID = /^[a-z0-9]+(-[a-z0-9]+)*$/;
// Some vendors wrap the spec: developer.sage.com serves its OpenAPI JSON inside a Markdown code fence.
// Zoho Books ships its OpenAPI as a zip of per-module files.
const EXTRACT = new Set(["markdown-json-fence", "zip-bundle"]);
// Specs we know about but CI cannot fetch: behind a login, or behind bot protection that refuses CI.
const MANUAL = new Set(["login", "bot-protection"]);
// OpenAPI Overlay documents (https://spec.openapis.org/overlay/) that fix a vendor's spec without forking it.
const OVERLAY_FORMATS = new Set(["openapi-3.0", "openapi-3.1", "swagger-2.0"]);
const OVERLAY_VERSION = /^1\.[01]\.\d+$/;
function overlayErrors(file, spec) {
  const errs = [];
  if (!/^overlays\/[a-z0-9-]+(\.[a-z0-9-]+)*\.ya?ml$/.test(file)) return ["overlay must be a file under overlays/, e.g. overlays/square.yaml"];
  if (!existsSync(join(ROOT, file))) return [`overlay ${file} does not exist`];
  if (!OVERLAY_FORMATS.has(spec.format)) errs.push(`overlay applies to OpenAPI or Swagger specs, not ${spec.format}`);
  if (spec.extract) errs.push("overlay can't be combined with extract");
  let doc;
  try {
    doc = parseYaml(readFileSync(join(ROOT, file), "utf8"));
  } catch (e) {
    return [...errs, `overlay ${file}: invalid YAML (${e.message})`];
  }
  if (!OVERLAY_VERSION.test(String(doc?.overlay ?? ""))) errs.push(`overlay ${file}: "overlay" must be a 1.0.x or 1.1.x version`);
  if (!doc?.info?.title || !doc?.info?.version) errs.push(`overlay ${file}: info.title and info.version are required`);
  if (doc?.extends && doc.extends !== spec.url) errs.push(`overlay ${file}: extends (${doc.extends}) must be the spec's url`);
  if (!Array.isArray(doc?.actions) || !doc.actions.length) errs.push(`overlay ${file}: actions must be a non-empty list`);
  (doc?.actions ?? []).forEach((a, i) => {
    if (typeof a?.target !== "string" || !a.target.startsWith("$")) errs.push(`overlay ${file} actions[${i}]: target must be a JSONPath starting with $`);
    if (a?.update === undefined && a?.remove !== true && a?.copy === undefined) errs.push(`overlay ${file} actions[${i}]: needs update, copy or remove: true`);
    if (!a?.description) errs.push(`overlay ${file} actions[${i}]: description is required (say what the vendor's spec gets wrong)`);
  });
  return errs;
}

const METHODS = ["get", "put", "post", "delete", "patch", "head", "options", "trace"];

// ---- validation ----
const errors = [];
const entries = [];
for (const file of readdirSync(join(ROOT, "connectors")).filter((f) => f.endsWith(".yaml")).sort()) {
  const where = `connectors/${file}`;
  let doc;
  try {
    doc = parseYaml(readFileSync(join(ROOT, "connectors", file), "utf8"));
  } catch (e) {
    errors.push(`${where}: invalid YAML (${e.message})`);
    continue;
  }
  const id = file.replace(/\.yaml$/, "");
  if (doc?.id !== id) errors.push(`${where}: id must equal the file name ("${id}")`);
  if (!ID.test(id)) errors.push(`${where}: id must be lowercase kebab-case`);
  if (!doc?.name) errors.push(`${where}: name is required`);
  if (!Array.isArray(doc?.specs)) {
    errors.push(`${where}: specs must be a list (use [] with a note when no spec is published)`);
    continue;
  }
  if (!doc.specs.length && !doc.notes) errors.push(`${where}: an entry with no specs needs notes saying why`);
  const names = new Set();
  doc.specs.forEach((s, i) => {
    const at = `${where} specs[${i}]`;
    if (!s?.name) errors.push(`${at}: name is required`);
    if (names.has(s?.name)) errors.push(`${at}: duplicate spec name "${s.name}"`);
    names.add(s?.name);
    if (!s?.url && !s?.path) errors.push(`${at}: url (preferred) or path is required`);
    if (s?.url && s?.path) errors.push(`${at}: give url or path, not both`);
    if (s?.url && !/^https:\/\//.test(s.url)) errors.push(`${at}: url must be https`);
    if (s?.path && !existsSync(join(ROOT, s.path))) errors.push(`${at}: path ${s.path} does not exist`);
    if (!FORMATS.has(s?.format)) errors.push(`${at}: format must be one of ${[...FORMATS].join(", ")}`);
    if (!PROVENANCE.has(s?.provenance)) errors.push(`${at}: provenance must be one of ${[...PROVENANCE].join(", ")}`);
    if (s?.extract && !EXTRACT.has(s.extract)) errors.push(`${at}: extract must be one of ${[...EXTRACT].join(", ")}`);
    if (s?.extract && !s?.url) errors.push(`${at}: extract applies to a fetched url; store an extracted spec as a plain path instead`);
    if (s?.manual && !MANUAL.has(s.manual)) errors.push(`${at}: manual must be one of ${[...MANUAL].join(", ")}`);
    if (s?.manual && !s?.notes) errors.push(`${at}: a spec CI can't fetch needs notes saying how to get it`);
    if (s?.overlay !== undefined) for (const m of overlayErrors(s.overlay, s)) errors.push(`${at}: ${m}`);
  });
  entries.push(doc);
}
if (errors.length) {
  console.error(errors.join("\n"));
  process.exit(1);
}
console.log(`${entries.length} connector entries valid, ${entries.reduce((n, e) => n + e.specs.length, 0)} specs.`);
if (VALIDATE_ONLY) process.exit(0);
if (ONLY && !entries.some((e) => e.id === ONLY)) {
  console.error(`--only ${ONLY}: no connectors/${ONLY}.yaml`);
  process.exit(1);
}

// ---- verification ----
const canonical = (v) =>
  Array.isArray(v) ? `[${v.map(canonical).join(",")}]`
  : v && typeof v === "object" ? `{${Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(",")}}`
  : JSON.stringify(v);
// Minimal zip reader (central directory, stored or deflated entries); enough for a vendor's spec bundle.
function unzip(buf) {
  let eocd = buf.length - 22;
  while (eocd >= 0 && buf.readUInt32LE(eocd) !== 0x06054b50) eocd--;
  if (eocd < 0) throw new Error("not a zip file");
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  const files = [];
  let total = 0; // decompressed bytes so far: a small archive must not inflate past the download cap
  for (let i = 0; i < count; i++) {
    const method = buf.readUInt16LE(p + 10);
    const size = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const local = buf.readUInt32LE(p + 42);
    const name = buf.toString("utf8", p + 46, p + 46 + nameLen);
    const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
    const raw = buf.subarray(start, start + size);
    if (!name.endsWith("/")) {
      if (method !== 0 && method !== 8) throw new Error(`${name}: compression method ${method} is not supported (stored or deflate only)`);
      const out = method === 8 ? inflateRawSync(raw, { maxOutputLength: MAX_BYTES - total }) : raw;
      total += out.length;
      if (total > MAX_BYTES) throw new Error("archive expands past the size cap");
      files.push({ name, text: out.toString("utf8") });
    }
    p += 46 + nameLen + extraLen + commentLen;
  }
  return files;
}

// Oracle's Financials spec is about 99 MB; anything far beyond that is a wrong URL or a hostile endpoint.
const MAX_BYTES = 200 * 1024 * 1024;

// Several entries share one file (Microsoft Graph backs Outlook, Calendar and Teams); fetch each URL once.
// A body stays cached only until the last spec that uses it has loaded it, so memory doesn't grow with the run.
const keyOf = (spec) => `${spec.url ?? spec.path}|${spec.extract ?? ""}`;
const uses = new Map();
const fetched = new Map();
async function load(spec) {
  const key = keyOf(spec);
  if (!fetched.has(key)) fetched.set(key, loadUncached(spec));
  const r = await fetched.get(key);
  const left = (uses.get(key) ?? 1) - 1;
  uses.set(key, left);
  if (left <= 0) fetched.delete(key);
  return { ...r }; // callers mutate their copy
}

async function loadUncached(spec) {
  if (spec.path) return { status: 200, body: readFileSync(join(ROOT, spec.path), "utf8") };
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 120000);
  try {
    const res = await fetch(spec.url, { signal: ctl.signal, headers: { "user-agent": "apideck-api-registry/2 (+https://github.com/apideck-io/api-registry)" } });
    if (!res.ok) {
      await res.body?.cancel(); // release the connection; the body of an error page isn't needed
      return { status: res.status, body: null };
    }
    // Stream with a cap instead of buffering an unbounded response.
    const chunks = [];
    let size = 0;
    for await (const chunk of res.body) {
      size += chunk.length;
      if (size > MAX_BYTES) {
        ctl.abort();
        return { status: res.status, body: null, error: `larger than ${MAX_BYTES / 1024 / 1024} MB` };
      }
      chunks.push(chunk);
    }
    const buf = Buffer.concat(chunks);
    if (spec.extract === "zip-bundle") return { status: res.status, body: null, bytes: buf };
    // Strip a UTF-8 byte-order mark, as res.text() would; some vendor files carry one.
    return { status: res.status, body: buf.toString("utf8").replace(/^\uFEFF/, "") };
  } catch (e) {
    return { status: 0, body: null, error: e.name === "AbortError" ? "timeout" : e.message };
  } finally {
    clearTimeout(timer);
  }
}

// Every format must show its identifying root, so a 200 error page or JSON error payload is a failure,
// not an "ok" spec with zero operations.
function inspect(format, body) {
  if (format === "xsd") {
    if (!/<(xsd?:)?schema[\s>]/.test(body)) throw new Error("no xsd:schema root");
    return { operations: (body.match(/<xsd?:element\s+name="[^"]+Rq"/g) ?? []).length };
  }
  if (format === "odata-edmx") {
    if (!/<edmx:Edmx[\s>]/.test(body)) throw new Error("no edmx:Edmx root");
    return { operations: (body.match(/<EntitySet\s/g) ?? []).length };
  }
  if (format === "graphql") {
    // SDL: count fields on the root Query and Mutation types. Introspection JSON: count their fields.
    if (body.trim().startsWith("{")) {
      const json = JSON.parse(body);
      const schema = json?.data?.__schema ?? json?.__schema;
      if (!schema?.types) throw new Error("no __schema in introspection result");
      // Root types can be renamed; introspection names them.
      const rootNames = [schema.queryType?.name, schema.mutationType?.name].filter(Boolean);
      const n = schema.types.filter((t) => rootNames.includes(t.name)).reduce((m, t) => m + (t.fields?.length ?? 0), 0);
      return { operations: n };
    }
    // Strip descriptions, strings and comments, then argument lists (which can hold {…} defaults), so a
    // type body ends at its own closing brace and description lines aren't counted as fields.
    let sdl = body.replace(/"""[\s\S]*?"""/g, "").replace(/"(?:\\.|[^"\\])*"/g, '""').replace(/#.*$/gm, "");
    for (let prev; prev !== sdl; ) {
      prev = sdl;
      sdl = sdl.replace(/\([^()]*\)/g, "");
    }
    // SDL can rename roots in a schema block (schema { query: QueryRoot }); default to Query and Mutation.
    const decl = sdl.match(/\bschema\s*\{([^}]*)\}/)?.[1] ?? "";
    const rootNames = [decl.match(/query\s*:\s*(\w+)/)?.[1] ?? "Query", decl.match(/mutation\s*:\s*(\w+)/)?.[1] ?? "Mutation"];
    const roots = [...sdl.matchAll(/(?:extend\s+)?type\s+(\w+)\b[^{]*\{([^}]*)\}/g)].filter((m) => rootNames.includes(m[1]));
    if (!roots.length) throw new Error(`no ${rootNames.join(" or ")} type`);
    // Drop argument lists first (they can span lines), then count "name:" field starts.
    // Every "name:" left in the body is a field (arguments are already gone), however many share a line.
    const fields = (block) => (block.match(/\b\w+\s*:/g) ?? []).length;
    return { operations: roots.reduce((n, m) => n + fields(m[2]), 0) };
  }
  // YAML is read with the failsafe schema so every scalar stays a string: unquoted `swagger: 2.0` or
  // `version: 1.10` would otherwise become the numbers 2 and 1.1.
  const doc = body.trim().startsWith("{") ? JSON.parse(body) : parseYaml(body, { schema: "failsafe" });
  if (!doc || typeof doc !== "object") throw new Error("not a JSON or YAML document");
  if (format === "google-discovery") {
    if (!doc.discoveryVersion || !doc.resources) throw new Error("no discoveryVersion or resources");
    let n = 0;
    const walk = (r) => {
      for (const res of Object.values(r ?? {})) {
        n += Object.keys(res.methods ?? {}).length;
        walk(res.resources);
      }
    };
    walk(doc.resources);
    return { operations: n, title: doc.title, apiVersion: doc.version, server: doc.rootUrl ? doc.rootUrl + (doc.servicePath ?? "") : null, doc };
  }
  if (format === "postman-2.1") {
    if (!doc.info || !Array.isArray(doc.item)) throw new Error("no info or item list");
    let n = 0;
    const walk = (items) => items?.forEach((it) => (it.request ? n++ : walk(it.item)));
    walk(doc.item);
    return { operations: n, title: doc.info?.name };
  }
  if (format === "asyncapi-2") {
    if (!String(doc.asyncapi ?? "").startsWith("2")) throw new Error("no asyncapi 2.x root");
    // A channel can carry both publish and subscribe; count the operations, not the channels.
    const n = Object.values(doc.channels ?? {}).reduce((m, c) => m + (c?.publish ? 1 : 0) + (c?.subscribe ? 1 : 0), 0);
    return { operations: n, title: doc.info?.title, apiVersion: doc.info?.version };
  }
  if (format === "swagger-2.0" && String(doc.swagger) !== "2.0") throw new Error("no swagger: 2.0 root");
  if (format.startsWith("openapi-") && !String(doc.openapi ?? "").startsWith("3")) throw new Error("no openapi 3.x root");
  // OpenAPI 3.1 allows a document with only webhooks or components; earlier versions require paths.
  const pathsOptional = String(doc.openapi ?? "").startsWith("3.1") && (doc.webhooks || doc.components);
  if ((!doc.paths || typeof doc.paths !== "object") && !pathsOptional) throw new Error("no paths");
  let n = 0;
  for (const item of Object.values(doc.paths ?? {})) for (const m of METHODS) if (item?.[m]) n++;
  const server = doc.servers?.[0]?.url ?? (doc.host ? `${doc.schemes?.[0] ?? "https"}://${doc.host}${doc.basePath ?? ""}` : null);
  return { operations: n, title: doc.info?.title, apiVersion: doc.info?.version, specVersion: doc.openapi ?? doc.swagger, server };
}

for (const e of entries) if (!ONLY || e.id === ONLY) for (const s of e.specs) if (!s.manual) uses.set(keyOf(s), (uses.get(keyOf(s)) ?? 0) + 1);

const indexPath = join(ROOT, "index.json");
const prev = existsSync(indexPath) ? JSON.parse(readFileSync(indexPath, "utf8")) : { connectors: {} };
const today = new Date().toISOString().slice(0, 10);
// No "checked on" stamps: index.json changes only when a spec does, so the nightly job opens a PR only on drift.
const out = { connectors: { ...prev.connectors } };
let failures = 0;

for (const e of entries) {
  if (ONLY && e.id !== ONLY) continue;
  const before = prev.connectors[e.id]?.specs ?? {};
  const specs = {};
  for (const s of e.specs) {
    const old = before[s.name] ?? {};
    // Recorded, never fetched: a login wall, or bot protection that refuses CI. Earlier figures stay.
    if (s.manual) {
      specs[s.name] = { ...old, status: `manual: ${s.manual}` };
      continue;
    }
    const r = await load(s);
    if (r.body && s.extract === "markdown-json-fence") {
      const m = r.body.match(/```json\s*\n([\s\S]*?)\n```/);
      r.body = m ? m[1] : null;
      if (!m) r.error = "no json fence found";
    }
    let bundle = null;
    if (r.bytes) {
      try {
        // Skip macOS resource forks (__MACOSX/, ._name.json): binary files with a spec-like name.
        bundle = unzip(r.bytes).filter((f) => /\.(json|ya?ml)$/i.test(f.name) && !/(^|\/)(__MACOSX\/|\._)/.test(f.name));
        if (!bundle.length) throw new Error("no JSON or YAML files inside");
        r.body = "zip"; // marks success; the hash below is of the zip bytes themselves
      } catch (err) {
        r.error = `bad zip: ${err.message}`;
      }
    }
    if (r.body === "") r.error = "empty response";
    if (!r.body) {
      failures++;
      specs[s.name] = { ...old, status: r.error ?? `HTTP ${r.status}` };
      console.log(`✗ ${e.id} · ${s.name}: ${specs[s.name].status}`);
      continue;
    }
    let info;
    try {
      if (bundle) {
        // One entry per module file; the bundle's count is their sum.
        const parts = bundle.map((f) => inspect(s.format, f.text));
        const one = (k) => [...new Set(parts.map((x) => x[k]).filter(Boolean))];
        const versions = one("apiVersion");
        info = {
          operations: parts.reduce((n, x) => n + (x.operations ?? 0), 0),
          files: bundle.length,
          // Each module has its own title; the bundle is named by the entry, with the module count beside it.
          title: s.name,
          apiVersion: versions.length === 1 ? versions[0] : versions.join(", ") || null,
          specVersion: parts[0]?.specVersion,
          server: parts.find((x) => x.server)?.server,
        };
      } else info = inspect(s.format, r.body);
    } catch (err) {
      failures++;
      specs[s.name] = { ...old, status: `unparseable: ${err.message.slice(0, 80)}` };
      console.log(`✗ ${e.id} · ${s.name}: unparseable`);
      continue;
    }
    // Google Discovery docs come back with a different key order on each request and re-stamp etag and
    // revision on every publish, with no change to the API. Hash a key-sorted copy without those fields,
    // or the nightly job would open a drift PR every night.
    const { doc, ...meta } = info;
    info = meta;
    // The entry's server is set by hand and wins; specs often carry placeholders (DefaultParameterValue,
    // {baseUrl}). The spec's own value is kept as specServer when they differ.
    if (s.server && info.server && info.server !== s.server) info.specServer = info.server;
    if (s.server) info.server = s.server;
    // A rebuilt zip changes its bytes (timestamps, compression) without any spec changing, so a bundle
    // is hashed on its files' names and contents.
    const hashed = doc
      ? canonical({ ...doc, etag: undefined, revision: undefined })
      : bundle
        ? canonical([...bundle].sort((a, b) => a.name.localeCompare(b.name)).map((f) => [f.name.replace(/^.*\//, ""), f.text]))
        : r.body;
    const sha256 = createHash("sha256").update(hashed).digest("hex");
    const changed = old.sha256 && old.sha256 !== sha256;
    // An overlay is applied to the fetched spec on every run. Its actions whose target no longer matches
    // anything are listed: the vendor fixed the mistake (drop the action) or moved it (update the target).
    let overlay;
    if (s.overlay) {
      const text = readFileSync(join(ROOT, s.overlay), "utf8");
      try {
        const parseSpec = () => (/^\s*[{[]/.test(r.body) ? JSON.parse(r.body) : parseYaml(r.body, { maxAliasCount: 10000 }));
        const overlaySet = parseYaml(text);
        const original = parseSpec();
        const res = await openapiOverlay(parseSpec(), { overlaySet });
        const unmatched = res.resultData.unusedActions.map((a) => a.target);
        // An update whose target is unchanged by the whole overlay is redundant: the vendor already says
        // what it adds (they fixed it), so the action can go.
        const redundant = overlaySet.actions
          .filter((a) => a.update !== undefined && !unmatched.includes(a.target))
          .filter((a) => canonical(resolveJsonPathValue(original, a.target)) === canonical(resolveJsonPathValue(res.data, a.target)))
          .map((a) => a.target);
        overlay = {
          file: s.overlay,
          sha256: createHash("sha256").update(text).digest("hex"),
          actions: res.resultData.totalActions,
          ...(unmatched.length ? { unmatched } : {}),
          ...(redundant.length ? { redundant } : {}),
        };
      } catch (err) {
        overlay = { file: s.overlay, error: err.message.slice(0, 120) };
      }
    }
    specs[s.name] = {
      status: "ok",
      sha256,
      // For a bundle, the size of its files: the archive's own size changes when it is merely rebuilt.
      bytes: bundle ? bundle.reduce((n, f) => n + Buffer.byteLength(f.text), 0) : Buffer.byteLength(r.body),
      ...Object.fromEntries(Object.entries(info).filter(([, v]) => v != null)),
      changedOn: changed || !old.sha256 ? today : old.changedOn,
      ...(overlay ? { overlay } : {}),
    };
    // Δ changed, + newly indexed, ↺ recovered from a failure, ✓ unchanged. The nightly PR body lists all but ✓.
    const mark = changed ? "Δ" : !old.sha256 ? "+" : old.status && old.status !== "ok" ? "↺" : "✓";
    const problems = overlay?.error
      ? [overlay.error]
      : [overlay?.unmatched?.length && `${overlay.unmatched.length} action(s) match nothing`, overlay?.redundant?.length && `${overlay.redundant.length} action(s) change nothing`].filter(Boolean);
    const stale = problems.length ? ` ⚠ overlay: ${problems.join("; ")}` : "";
    console.log(`${mark} ${e.id} · ${s.name}: ${info.operations ?? "?"} operations${stale}`);
  }
  out.connectors[e.id] = { name: e.name, specs };
}
// Entries removed from connectors/ leave the index too.
for (const id of Object.keys(out.connectors)) if (!entries.some((e) => e.id === id)) delete out.connectors[id];

writeFileSync(indexPath, JSON.stringify(out, null, 2) + "\n");
console.log(`\nindex.json written; ${failures} spec(s) failed to fetch or parse.`);
