// Validates every connectors/*.yaml entry and, unless --validate-only, fetches each spec and writes
// index.json: sha256, operation count, title, API version and fetch status per spec.
//
//   node scripts/verify.mjs [--validate-only] [--only <id>]
//
// index.json is generated; never edit it by hand. A spec that fails to fetch keeps its last good
// sha256 and operation count, with `status` recording the failure, so one outage doesn't erase history.

import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";

const ROOT = new URL("..", import.meta.url).pathname;
const args = process.argv.slice(2);
const VALIDATE_ONLY = args.includes("--validate-only");
const ONLY = args.includes("--only") ? args[args.indexOf("--only") + 1] : null;

const FORMATS = new Set(["openapi-3.0", "openapi-3.1", "swagger-2.0", "google-discovery", "asyncapi-2", "postman-2.1", "odata-edmx", "xsd", "graphql"]);
const PROVENANCE = new Set(["vendor", "third-party", "community", "fork"]);
const ID = /^[a-z0-9]+(-[a-z0-9]+)*$/;
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
    if (s?.url && !/^https:\/\//.test(s.url)) errors.push(`${at}: url must be https`);
    if (s?.path && !existsSync(join(ROOT, s.path))) errors.push(`${at}: path ${s.path} does not exist`);
    if (!FORMATS.has(s?.format)) errors.push(`${at}: format must be one of ${[...FORMATS].join(", ")}`);
    if (!PROVENANCE.has(s?.provenance)) errors.push(`${at}: provenance must be one of ${[...PROVENANCE].join(", ")}`);
  });
  entries.push(doc);
}
if (errors.length) {
  console.error(errors.join("\n"));
  process.exit(1);
}
console.log(`${entries.length} connector entries valid, ${entries.reduce((n, e) => n + e.specs.length, 0)} specs.`);
if (VALIDATE_ONLY) process.exit(0);

// ---- verification ----
async function load(spec) {
  if (spec.path) return { status: 200, body: readFileSync(join(ROOT, spec.path), "utf8") };
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 60000);
  try {
    const res = await fetch(spec.url, { signal: ctl.signal, headers: { "user-agent": "apideck-api-registry/2 (+https://github.com/apideck-io/api-registry)" } });
    return { status: res.status, body: res.ok ? await res.text() : null };
  } catch (e) {
    return { status: 0, body: null, error: e.name === "AbortError" ? "timeout" : e.message };
  } finally {
    clearTimeout(timer);
  }
}

function inspect(format, body) {
  if (format === "xsd") return { operations: (body.match(/<xsd?:element\s+name="[^"]+Rq"/g) ?? []).length || null };
  if (format === "odata-edmx") return { operations: (body.match(/<EntitySet\s/g) ?? []).length };
  if (format === "graphql") return {};
  const doc = body.trim().startsWith("{") ? JSON.parse(body) : parseYaml(body);
  if (format === "google-discovery") {
    let n = 0;
    const walk = (r) => {
      for (const res of Object.values(r ?? {})) {
        n += Object.keys(res.methods ?? {}).length;
        walk(res.resources);
      }
    };
    walk(doc.resources);
    return { operations: n, title: doc.title, apiVersion: doc.version, server: doc.rootUrl ? doc.rootUrl + (doc.servicePath ?? "") : null };
  }
  if (format === "postman-2.1") {
    let n = 0;
    const walk = (items) => items?.forEach((it) => (it.request ? n++ : walk(it.item)));
    walk(doc.item);
    return { operations: n, title: doc.info?.name };
  }
  if (format === "asyncapi-2") return { operations: Object.keys(doc.channels ?? {}).length, title: doc.info?.title, apiVersion: doc.info?.version };
  let n = 0;
  for (const item of Object.values(doc.paths ?? {})) for (const m of METHODS) if (item?.[m]) n++;
  const server = doc.servers?.[0]?.url ?? (doc.host ? `${doc.schemes?.[0] ?? "https"}://${doc.host}${doc.basePath ?? ""}` : null);
  return { operations: n, title: doc.info?.title, apiVersion: doc.info?.version, specVersion: doc.openapi ?? doc.swagger, server };
}

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
    const r = await load(s);
    if (!r.body) {
      failures++;
      specs[s.name] = { ...old, status: r.error ?? `HTTP ${r.status}` };
      console.log(`✗ ${e.id} · ${s.name}: ${specs[s.name].status}`);
      continue;
    }
    let info;
    try {
      info = inspect(s.format, r.body);
    } catch (err) {
      failures++;
      specs[s.name] = { ...old, status: `unparseable: ${err.message.slice(0, 80)}` };
      console.log(`✗ ${e.id} · ${s.name}: unparseable`);
      continue;
    }
    const sha256 = createHash("sha256").update(r.body).digest("hex");
    const changed = old.sha256 && old.sha256 !== sha256;
    specs[s.name] = {
      status: "ok",
      sha256,
      bytes: Buffer.byteLength(r.body),
      ...Object.fromEntries(Object.entries(info).filter(([, v]) => v != null)),
      changedOn: changed || !old.sha256 ? today : old.changedOn,
    };
    console.log(`${changed ? "Δ" : "✓"} ${e.id} · ${s.name}: ${info.operations ?? "?"} operations`);
  }
  out.connectors[e.id] = { name: e.name, specs };
}
// Entries removed from connectors/ leave the index too.
for (const id of Object.keys(out.connectors)) if (!entries.some((e) => e.id === id)) delete out.connectors[id];

writeFileSync(indexPath, JSON.stringify(out, null, 2) + "\n");
console.log(`\nindex.json written; ${failures} spec(s) failed to fetch or parse.`);
