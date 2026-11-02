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
import { existsSync, mkdirSync, readFileSync, readdirSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { parse as parseYaml } from "yaml";
import { createRequire } from "node:module";
import openapiFormat from "openapi-format";
import { buildASTSchema, introspectionFromSchema, parse as parseGraphQL } from "graphql";
import { scanText, sdlDescriptions, suspiciousFingerprint, surfaceOf, xmlTexts } from "./spec-safety.mjs";

const { openapiOverlay, resolveJsonPathValue } = openapiFormat;
// The JSONPath parser openapi-format applies overlays with, resolved through it rather than declared
// twice, so validation accepts exactly what the nightly run can apply.
const jsonpathly = createRequire(createRequire(import.meta.url).resolve("openapi-format"))("jsonpathly");
// openapi-format rewrites RFC 9535 filters ([?@.x]) to the engine's form ([?(@.x)]) before parsing.
const jsonPathSyntaxError = (target) => {
  try {
    jsonpathly.parse(target.replace(/\[\?(@|\$)([^\]]*)\]/g, "[?($1$2)]"));
    return null;
  } catch (e) {
    return e.message.split("\n")[0].slice(0, 100);
  }
};
const nonEmpty = (v) => typeof v === "string" && v.trim() !== "";

const ROOT = fileURLToPath(new URL("..", import.meta.url)); // decoded, so paths with spaces work
const args = process.argv.slice(2);
const VALIDATE_ONLY = args.includes("--validate-only");
const onlyEq = args.find((a) => a.startsWith("--only="));
const ONLY = onlyEq ? onlyEq.slice(7) : args.includes("--only") ? args[args.indexOf("--only") + 1] ?? "" : null;
if (ONLY === "" || ONLY?.startsWith("--")) {
  console.error("--only needs a connector id");
  process.exit(1);
}

const FORMATS = new Set(["openapi-3.0", "openapi-3.1", "swagger-2.0", "google-discovery", "asyncapi-2", "postman-2.0", "postman-2.1", "odata-edmx", "xsd", "graphql"]);
const PROVENANCE = new Set(["vendor", "third-party", "community", "fork"]);
const ID = /^[a-z0-9]+(-[a-z0-9]+)*$/;
// Some vendors wrap the spec: developer.sage.com serves its OpenAPI JSON inside a Markdown code fence.
// Zoho Books ships its OpenAPI as a zip of per-module files.
// Fortnox embeds its OpenAPI in a Redoc page (window.__redoc_state) with no raw file to link.
// Some GraphQL APIs publish no SDL but answer an anonymous introspection query (Wave, Access Financials).
// swagger-ui-express pages embed the spec as options.swaggerDoc in swagger-ui-init.js (Minox).
const EXTRACT = new Set(["markdown-json-fence", "zip-bundle", "redoc-state", "graphql-introspection", "swagger-ui-init"]);
// Full enough that changed argument types, return types, nullability, input fields or enum values show as drift.
// Eight levels, as graphql-js uses: enough for [[Foo!]!]! and deeper wrappings.
const TYPE_REF = "kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } }";
const INTROSPECTION = `{ __schema { queryType { name } mutationType { name } subscriptionType { name } types {
  kind name
  fields(includeDeprecated: true) { name isDeprecated args { name defaultValue type { ${TYPE_REF} } } type { ${TYPE_REF} } }
  inputFields { name defaultValue type { ${TYPE_REF} } }
  enumValues(includeDeprecated: true) { name isDeprecated }
  interfaces { name } possibleTypes { name }
} } }`;
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
  if (spec.manual) errs.push("overlay can't be combined with manual: the nightly check never fetches the spec to apply it");
  let doc;
  try {
    doc = parseYaml(readFileSync(join(ROOT, file), "utf8"));
  } catch (e) {
    return [...errs, `overlay ${file}: invalid YAML (${e.message})`];
  }
  if (!OVERLAY_VERSION.test(String(doc?.overlay ?? ""))) errs.push(`overlay ${file}: "overlay" must be a 1.0.x or 1.1.x version`);
  if (!nonEmpty(doc?.info?.title) || !nonEmpty(String(doc?.info?.version ?? ""))) errs.push(`overlay ${file}: info.title and info.version are required strings`);
  if (doc?.extends && doc.extends !== spec.url) errs.push(`overlay ${file}: extends (${doc.extends}) must be the spec's url`);
  if (!Array.isArray(doc?.actions) || !doc.actions.length) errs.push(`overlay ${file}: actions must be a non-empty list`);
  (doc?.actions ?? []).forEach((a, i) => {
    const at = `overlay ${file} actions[${i}]`;
    if (typeof a?.target !== "string" || !a.target.startsWith("$")) errs.push(`${at}: target must be a JSONPath starting with $`);
    else {
      const syntax = jsonPathSyntaxError(a.target);
      if (syntax) errs.push(`${at}: target is not valid JSONPath (${syntax})`);
    }
    // One operation per action, with a payload of the right type.
    const ops = ["update", "remove", "copy"].filter((k) => a?.[k] !== undefined);
    if (!ops.length) errs.push(`${at}: needs update, copy or remove: true`);
    if (ops.length > 1) errs.push(`${at}: give one of update, copy or remove, not ${ops.join(" and ")}`);
    if (a?.update === null) errs.push(`${at}: update can't be null`);
    if (a?.remove !== undefined && a.remove !== true) errs.push(`${at}: remove must be true`);
    if (a?.copy !== undefined) {
      if (typeof a.copy !== "string" || !a.copy.startsWith("$")) errs.push(`${at}: copy must be a JSONPath to the source node`);
      else if (jsonPathSyntaxError(a.copy)) errs.push(`${at}: copy is not valid JSONPath`);
      if (!/^1\.1\./.test(String(doc.overlay))) errs.push(`${at}: copy needs overlay 1.1.x`);
    }
    if (!nonEmpty(a?.description)) errs.push(`${at}: description is required (say what the vendor's spec gets wrong)`);
  });
  return errs;
}

// The index's coverage always follows the entry: a spec that stops being auth-only must not keep the mark.
const withoutCoverage = ({ coverage, ...rest }) => rest;

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
  // Apps Apideck doesn't connect yet are listed too, marked apideck: false (the id is then the app's common slug).
  if (doc?.apideck !== undefined && doc.apideck !== false) errors.push(`${where}: apideck is only set to false, for an app Apideck doesn't connect yet`);
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
    // Null prototype, so a malformed value like `extract: toString` is a validation error, not a TypeError.
    const extractFits = Object.assign(Object.create(null), { "graphql-introspection": ["graphql"], "swagger-ui-init": ["openapi-3.0", "openapi-3.1", "swagger-2.0"], "redoc-state": ["openapi-3.0", "openapi-3.1", "swagger-2.0"], "markdown-json-fence": ["openapi-3.0", "openapi-3.1", "swagger-2.0"], "zip-bundle": ["openapi-3.0", "openapi-3.1", "swagger-2.0"] });
    if (s?.extract && extractFits[s.extract] && !extractFits[s.extract].includes(s?.format)) errors.push(`${at}: extract ${s.extract} doesn't apply to format ${s?.format}`);
    if (s?.extract && !s?.url) errors.push(`${at}: extract applies to a fetched url; store an extracted spec as a plain path instead`);
    if (s?.manual && !MANUAL.has(s.manual)) errors.push(`${at}: manual must be one of ${[...MANUAL].join(", ")}`);
    if (s?.manual && !s?.notes) errors.push(`${at}: a spec CI can't fetch needs notes saying how to get it`);
    if (s?.overlay !== undefined) for (const m of overlayErrors(s.overlay, s)) errors.push(`${at}: ${m}`);
    // An auth-only spec describes how to authenticate (servers, security schemes, scopes) and no endpoints:
    // written here, from the vendor's own documentation, for an app that publishes no spec.
    if (s?.coverage === undefined && s?.path && /\.(ya?ml|json)$/.test(s.path) && existsSync(join(ROOT, s.path))) {
      let marked = false;
      try {
        marked = parseYaml(readFileSync(join(ROOT, s.path), "utf8"))?.["x-auth-only"] === true; // YAML parses JSON too
      } catch {
        marked = false; // not this check's concern: the fetch reports an unparseable spec
      }
      if (marked) errors.push(`${at}: ${s.path} is marked x-auth-only; declare coverage: auth-only`);
    }
    if (s?.coverage !== undefined) {
      if (s.coverage !== "auth-only") errors.push(`${at}: coverage is only set to auth-only`);
      else {
        if (!s?.path?.startsWith("specs/")) errors.push(`${at}: an auth-only spec is authored here, as a path under specs/`);
        // Only YAML and JSON can carry the x-auth-only marker the check above looks for.
        if (s?.path && !/\.(ya?ml|json)$/.test(s.path)) errors.push(`${at}: an auth-only spec is a .yaml, .yml or .json file`);
        if (s?.format !== "openapi-3.1") errors.push(`${at}: an auth-only spec is openapi-3.1 (3.1 allows a document with no paths)`);
        if (!s?.notes) errors.push(`${at}: an auth-only spec needs notes saying it describes authentication only`);
        if (s?.path && existsSync(join(ROOT, s.path))) {
          const isObj = (v) => Boolean(v) && typeof v === "object" && !Array.isArray(v);
          const httpsUrl = (v) => typeof v === "string" && /^https:\/\/[^\s/]+\S*$/.test(v);
          let spec;
          try {
            spec = parseYaml(readFileSync(join(ROOT, s.path), "utf8"));
          } catch (e) {
            errors.push(`${at}: ${s.path} is not valid YAML (${e.message})`);
          }
          if (spec !== undefined && !isObj(spec)) errors.push(`${at}: ${s.path} is not an OpenAPI document`);
          else if (spec) {
            for (const key of ["paths", "webhooks", "x-ms-paths"])
              if (spec[key] !== undefined && (!isObj(spec[key]) || Object.keys(spec[key]).length)) errors.push(`${at}: an auth-only spec lists no endpoints; ${s.path} has ${key} that isn't an empty map`);
            if (!Array.isArray(spec.servers) || typeof spec.servers[0]?.url !== "string" || !spec.servers[0].url.trim()) errors.push(`${at}: an auth-only spec names the API's server`);
            if (!isObj(spec.components?.securitySchemes) || !Object.keys(spec.components.securitySchemes).length) errors.push(`${at}: an auth-only spec needs components.securitySchemes`);
            if (spec["x-auth-only"] !== true) errors.push(`${at}: an auth-only spec sets x-auth-only: true`);
            for (const [name, scheme] of Object.entries(spec.components?.securitySchemes ?? {})) {
              // Written here, so schemes are inline: a $ref would need resolving before any of this could check it.
              if (isObj(scheme) && scheme.$ref !== undefined) errors.push(`${at}: securitySchemes.${name} is defined inline in an auth-only spec, not as a $ref`);
              else if (!isObj(scheme) || !["apiKey", "http", "mutualTLS", "oauth2", "openIdConnect"].includes(scheme.type)) errors.push(`${at}: securitySchemes.${name} needs a type: apiKey, http, mutualTLS, oauth2 or openIdConnect`);
              else if (scheme.type === "openIdConnect" && !httpsUrl(scheme.openIdConnectUrl)) errors.push(`${at}: ${name} is openIdConnect and needs an https openIdConnectUrl`);
              else if (scheme.type === "apiKey" && (typeof scheme.name !== "string" || !scheme.name.trim() || !["query", "header", "cookie"].includes(scheme.in))) errors.push(`${at}: ${name} is apiKey and needs a name and in: query, header or cookie`);
              else if (scheme.type === "http" && (typeof scheme.scheme !== "string" || !scheme.scheme.trim())) errors.push(`${at}: ${name} is http and needs a scheme (basic, bearer…)`);
              else if (scheme.type === "oauth2") {
                if (!isObj(scheme.flows) || !Object.keys(scheme.flows).length) errors.push(`${at}: ${name} is oauth2 and needs flows`);
                for (const [kind, flow] of Object.entries(isObj(scheme.flows) ? scheme.flows : {})) {
                  if (!["authorizationCode", "implicit", "clientCredentials", "password"].includes(kind)) errors.push(`${at}: ${name}.flows.${kind} is not an OAuth 2.0 flow`);
                  if (!isObj(flow?.scopes)) errors.push(`${at}: ${name}.flows.${kind} needs scopes (an empty map when the vendor lists none)`);
                  else if (Object.values(flow.scopes).some((d) => typeof d !== "string")) errors.push(`${at}: ${name}.flows.${kind} scopes map each scope to a string description`);
                  if ((kind === "authorizationCode" || kind === "implicit") && !httpsUrl(flow?.authorizationUrl)) errors.push(`${at}: ${name}.flows.${kind} needs an https authorizationUrl`);
                  if (kind !== "implicit" && !httpsUrl(flow?.tokenUrl)) errors.push(`${at}: ${name}.flows.${kind} needs an https tokenUrl`);
                  if (flow?.refreshUrl !== undefined && !httpsUrl(flow.refreshUrl)) errors.push(`${at}: ${name}.flows.${kind} refreshUrl must be https`);
                }
              }
              // Values beyond the URLs, on any scheme type, are checked and cited too, or left out.
              if (isObj(scheme)) {
                const method = scheme["x-token-endpoint-auth-method"];
                if (method !== undefined && !["client_secret_basic", "client_secret_post"].includes(method)) errors.push(`${at}: ${name} x-token-endpoint-auth-method is client_secret_basic or client_secret_post`);
                if (method !== undefined && !spec["x-sources"]?.tokenEndpointAuthMethod) errors.push(`${at}: x-sources.tokenEndpointAuthMethod is required when ${name} sets x-token-endpoint-auth-method`);
                if (scheme["x-pkce-required"] !== undefined && typeof scheme["x-pkce-required"] !== "boolean") errors.push(`${at}: ${name} x-pkce-required is true or false`);
                if (scheme["x-pkce-required"] !== undefined && !spec["x-sources"]?.pkce) errors.push(`${at}: x-sources.pkce is required when ${name} sets x-pkce-required`);
              }
            }
            if (!isObj(spec["x-sources"])) errors.push(`${at}: an auth-only spec cites its sources in x-sources`);
            else for (const [k, v] of Object.entries(spec["x-sources"])) if (typeof v !== "string" || !/^https:\/\/\S+$/.test(v)) errors.push(`${at}: x-sources.${k} must be one https URL`);
            if (isObj(spec["x-sources"])) {
              const flows = Object.values(spec.components?.securitySchemes ?? {}).flatMap((sc) => Object.values(sc?.flows ?? {}));
              const schemes = Object.values(spec.components?.securitySchemes ?? {}).filter(isObj);
              const needed = ["server", ...(flows.some((f) => f?.authorizationUrl) ? ["authorizationUrl"] : []), ...(flows.some((f) => f?.tokenUrl) ? ["tokenUrl"] : []), ...(schemes.some((sc) => sc.openIdConnectUrl) ? ["openIdConnectUrl"] : [])];
              for (const k of needed) if (!spec["x-sources"][k]) errors.push(`${at}: x-sources.${k} is required`);
              // A citation for a value the spec doesn't state is left over from an edit.
              const states = { tokenEndpointAuthMethod: schemes.some((sc) => sc["x-token-endpoint-auth-method"] !== undefined), pkce: schemes.some((sc) => sc["x-pkce-required"] !== undefined), scopes: flows.some((f) => Object.keys(f?.scopes ?? {}).length), openIdConnectUrl: schemes.some((sc) => sc.openIdConnectUrl), authorizationUrl: flows.some((f) => f?.authorizationUrl), tokenUrl: flows.some((f) => f?.tokenUrl) };
              for (const [k, set] of Object.entries(states)) if (spec["x-sources"][k] && !set) errors.push(`${at}: x-sources.${k} cites a value the spec doesn't set`);
              for (const k of Object.keys(spec["x-sources"])) if (k !== "server" && !(k in states)) errors.push(`${at}: x-sources.${k} isn't a value an auth-only spec cites (server, ${Object.keys(states).join(", ")})`);
            }
            const listsScopes = Object.values(spec.components?.securitySchemes ?? {}).some((sc) => Object.values(sc?.flows ?? {}).some((f) => Object.keys(f?.scopes ?? {}).length));
            if (isObj(spec["x-sources"]) && listsScopes && !spec["x-sources"].scopes) errors.push(`${at}: x-sources.scopes is required when the spec lists scopes`);
          }
        }
      }
    }
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
// The JSON object starting at `start`, found by matching braces outside strings (code follows it in the page).
function balancedObject(text, start) {
  let depth = 0;
  let inString = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (ch === "\\") i++;
      else if (ch === '"') inString = false;
    } else if (ch === '"') inString = true;
    else if (ch === "{") depth++;
    else if (ch === "}" && --depth === 0) return text.slice(start, i + 1);
  }
  throw new Error("unterminated object");
}
const canonical = (v) =>
  Array.isArray(v) ? `[${v.map(canonical).join(",")}]`
  : v && typeof v === "object" ? `{${Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(",")}}`
  : JSON.stringify(v);
// Some vendors render "now" into their spec: a parameter's default is today's date (Hugging Face's
// usage ranges), so every fetch differs. Those values are left out of the hash; the file is still
// recorded as served.
const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?$/;
// Cheap pre-check on the raw text, so only files that need it are parsed for hashing.
const GENERATED_DATE_DEFAULT = /["']?default["']?\s*:\s*["']?\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/;
const withoutGeneratedDates = (v) =>
  Array.isArray(v) ? v.map(withoutGeneratedDates)
  : v && typeof v === "object"
    ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, k === "default" && typeof x === "string" && ISO_TIMESTAMP.test(x) ? "<generated date>" : withoutGeneratedDates(x)]))
    : v;
// The first value stored under `key` anywhere in a parsed JSON document (depth-first).
function findKey(v, key) {
  if (!v || typeof v !== "object") return undefined;
  if (!Array.isArray(v) && Object.hasOwn(v, key)) return v[key];
  for (const x of Object.values(v)) {
    const found = findKey(x, key);
    if (found !== undefined) return found;
  }
  return undefined;
}
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
  if (spec.path) {
    const buf = readFileSync(join(ROOT, spec.path));
    return { status: 200, body: buf.toString("utf8"), fetchSha256: createHash("sha256").update(buf).digest("hex") };
  }
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 120000);
  try {
    const ua = { "user-agent": "apideck-api-registry/2 (+https://github.com/apideck-io/api-registry)" };
    const res =
      spec.extract === "graphql-introspection"
        ? await fetch(spec.url, { method: "POST", signal: ctl.signal, headers: { ...ua, "content-type": "application/json" }, body: JSON.stringify({ query: INTROSPECTION }) })
        : await fetch(spec.url, { signal: ctl.signal, headers: ua });
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
    // The hash of the exact bytes served, before any unwrapping: a consumer that downloads the same URL
    // compares its own bytes with this to know it got the file this check saw.
    const fetchSha256 = createHash("sha256").update(buf).digest("hex");
    if (spec.extract === "zip-bundle") return { status: res.status, body: null, bytes: buf, fetchSha256 };
    // Strip a UTF-8 byte-order mark, as res.text() would; some vendor files carry one.
    return { status: res.status, body: buf.toString("utf8").replace(/^\uFEFF/, ""), fetchSha256 };
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
    return { operations: (body.match(/<xsd?:element\s+name="[^"]+Rq"/g) ?? []).length, ...flagged(scanText(xmlTexts(body), { positional: false })) };
  }
  if (format === "odata-edmx") {
    if (!/<edmx:Edmx[\s>]/.test(body)) throw new Error("no edmx:Edmx root");
    return { operations: (body.match(/<EntitySet\s/g) ?? []).length, ...flagged(scanText(xmlTexts(body), { positional: false })) };
  }
  if (format === "graphql") {
    // SDL: count fields on the root Query and Mutation types. Introspection JSON: count their fields.
    if (body.trim().startsWith("{")) {
      const json = JSON.parse(body);
      // A GraphQL error response can still be HTTP 200; so can a schema with no query root.
      if (Array.isArray(json?.errors) && json.errors.length) throw new Error(`introspection returned errors: ${String(json.errors[0]?.message ?? "").slice(0, 60)}`);
      const schema = json?.data?.__schema ?? json?.__schema;
      if (!schema?.types) throw new Error("no __schema in introspection result");
      if (!schema.queryType?.name) throw new Error("introspection has no query root");
      // Root types can be renamed; introspection names them.
      const rootNames = [schema.queryType?.name, schema.mutationType?.name].filter(Boolean);
      const n = schema.types.filter((t) => rootNames.includes(t.name)).reduce((m, t) => m + (t.fields?.length ?? 0), 0);
      if (!n) throw new Error("the root types have no fields");
      return { operations: n, ...flagged(scanText(schema)) };
    }
    // SDL is parsed with graphql-js and published as an introspection result (derived/), so consumers read
    // one GraphQL format. assumeValidSDL: vendors' SDL often uses directives it doesn't declare.
    try {
      const introspection = introspectionFromSchema(buildASTSchema(parseGraphQL(body), { assumeValidSDL: true }), { descriptions: true });
      const schema = introspection.__schema;
      if (!schema.queryType?.name) throw new Error("no query root");
      const roots = [schema.queryType?.name, schema.mutationType?.name].filter(Boolean);
      const n = schema.types.filter((t) => roots.includes(t.name)).reduce((m, t) => m + (t.fields?.length ?? 0), 0);
      if (!n) throw new Error("the root types have no fields");
      // Parsed by graphql-js, so its descriptions are scanned from the schema rather than found by regex.
      return { operations: n, introspection, ...flagged(scanText(introspection, { positional: false })) };
    } catch (err) {
      if (/no query root|no fields/.test(err.message)) throw err;
      // Not parseable by graphql-js: count fields as before, without a derived file, and say why.
      return { ...countSdlFields(body), derivedError: err.message.split("\n")[0].slice(0, 100), ...flagged(scanText(sdlDescriptions(body), { positional: false })) };
    }
  }
  return inspectDocument(format, body);
}

function countSdlFields(body) {
  {
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
    if (!roots.some((m) => m[1] === rootNames[0])) throw new Error(`no ${rootNames[0]} root type`);
    // Drop argument lists first (they can span lines), then count "name:" field starts.
    // Every "name:" left in the body is a field (arguments are already gone), however many share a line.
    const fields = (block) => (block.match(/\b\w+\s*:/g) ?? []).length;
    const total = roots.reduce((n, m) => n + fields(m[2]), 0);
    if (!total) throw new Error("the root types have no fields");
    return { operations: total };
  }
}

function inspectDocument(format, body) {
  // YAML is read with the failsafe schema so every scalar stays a string: unquoted `swagger: 2.0` or
  // `version: 1.10` would otherwise become the numbers 2 and 1.1.
  const doc = body.trim().startsWith("{") ? JSON.parse(body) : parseYaml(body, { schema: "failsafe", maxAliasCount: 10000 });
  if (!doc || typeof doc !== "object") throw new Error("not a JSON or YAML document");
  const info = inspectParsed(format, doc);
  // Where calls go and how they authenticate, and any text aimed at a model (scripts/spec-safety.mjs).
  const surface = surfaceOf(format, doc);
  return { ...info, ...(surface ? { surface } : {}), ...flagged(scanText(doc)) };
}

// A failure that holds the nightly PR: the spec resolved last time, or has never been checked. One that was
// already failing is listed but doesn't block every night until the vendor fixes it.
// A manual: status (login, bot protection) was never fetched, so a failure after it is new too.
const newlyFailing = (old) => !old.status || old.status === "ok" || String(old.status).startsWith("manual");

// What index.json keeps of flagged text: a few samples to read, and a fingerprint of all of it to compare.
const flagged = ({ samples, hits }) => (hits.length ? { suspicious: samples, suspiciousSha: suspiciousFingerprint(hits) } : {});

function inspectParsed(format, doc) {
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
  if (format === "postman-2.0" || format === "postman-2.1") {
    if (!doc.info || !Array.isArray(doc.item)) throw new Error("no info or item list");
    let n = 0;
    const walk = (items) => items?.forEach((it) => (it.request ? n++ : walk(it.item)));
    walk(doc.item);
    // The collection names its schema version in info.schema (…/collection/v2.0.0/collection.json).
    const schema = /\/v(\d+\.\d+\.\d+)\//.exec(String(doc.info.schema ?? ""))?.[1];
    return { operations: n, title: doc.info?.name, ...(schema ? { specVersion: schema } : {}) };
  }
  if (format === "asyncapi-2") {
    if (!String(doc.asyncapi ?? "").startsWith("2")) throw new Error("no asyncapi 2.x root");
    // A channel can carry both publish and subscribe; count the operations, not the channels.
    const n = Object.values(doc.channels ?? {}).reduce((m, c) => m + (c?.publish ? 1 : 0) + (c?.subscribe ? 1 : 0), 0);
    return { operations: n, title: doc.info?.title, apiVersion: doc.info?.version };
  }
  if (format === "swagger-2.0" && String(doc.swagger) !== "2.0") throw new Error("no swagger: 2.0 root");
  if (format.startsWith("openapi-") && !String(doc.openapi ?? "").startsWith("3")) throw new Error("no openapi 3.x root");
  // OpenAPI 3.1 and later allow a document with only webhooks or components; earlier versions require paths.
  const isMap = (v) => Boolean(v) && typeof v === "object" && !Array.isArray(v);
  const pathsOptional = /^3\.[1-9]/.test(String(doc.openapi ?? "")) && (isMap(doc.webhooks) || isMap(doc.components));
  if ((!doc.paths || typeof doc.paths !== "object") && !pathsOptional) throw new Error("no paths");
  let n = 0;
  // OpenAPI 3.2 adds the query method and additionalOperations (custom HTTP methods) on a path item.
  // Azure specs put paths that differ only by query in x-ms-paths; they're operations too.
  for (const item of [...Object.values(doc.paths ?? {}), ...Object.values(doc["x-ms-paths"] ?? {})]) {
    for (const m of [...METHODS, "query"]) if (item?.[m]) n++;
    if (item?.additionalOperations && typeof item.additionalOperations === "object") n += Object.keys(item.additionalOperations).length;
  }
  const server = doc.servers?.[0]?.url ?? (doc.host ? `${doc.schemes?.[0] ?? "https"}://${doc.host}${doc.basePath ?? ""}` : null);
  // OpenAPI and Swagger require info.title and info.version. A vendor file without them still describes its
  // operations, so it's kept, and the gap is recorded and flagged in the nightly PR.
  // Both must be non-empty strings (a JSON number such as version: 1 is not a valid info.version).
  const problem = (k) => {
    const v = doc.info?.[k];
    if (v === undefined || v === null || v === "") return `no info.${k}`;
    if (typeof v !== "string") return `info.${k} is a ${typeof v}, not a string`;
    return v.trim() ? null : `info.${k} is blank`;
  };
  const issues = ["title", "version"].map(problem).filter(Boolean);
  return { operations: n, title: doc.info?.title, apiVersion: doc.info?.version, specVersion: doc.openapi ?? doc.swagger, server, ...(issues.length ? { specIssues: issues.join(", ") } : {}) };
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
      specs[s.name] = { ...withoutCoverage(old), ...(s.coverage ? { coverage: s.coverage } : {}), status: `manual: ${s.manual}` };
      continue;
    }
    const r = await load(s);
    if (r.body && s.extract === "redoc-state") {
      const at = r.body.search(/__redoc_state\s*=\s*\{/);
      try {
        // A Redoc page (window.__redoc_state = { spec: { data } }), or a Redocly portal's Gatsby page data
        // (Drata), where the same store is a JSON string in a redocStoreStr field: { definition: { data } }.
        const spec =
          at >= 0
            ? JSON.parse(balancedObject(r.body, r.body.indexOf("{", at)))?.spec?.data
            : /^\s*\{/.test(r.body)
              ? JSON.parse(findKey(JSON.parse(r.body), "redocStoreStr") ?? "null")?.definition?.data
              : null;
        r.body = spec ? JSON.stringify(spec) : null;
        if (!spec) r.error = "no __redoc_state spec found";
      } catch (err) {
        r.body = null;
        r.error = `bad __redoc_state: ${err.message.slice(0, 60)}`;
      }
    }
    if (r.body && s.extract === "swagger-ui-init") {
      const at = r.body.search(/["']?swaggerDoc["']?\s*:\s*\{/);
      try {
        r.body = at >= 0 ? balancedObject(r.body, r.body.indexOf("{", at)) : null;
        if (!r.body) r.error = "no swaggerDoc in the init script";
      } catch (err) {
        r.body = null;
        r.error = `bad swaggerDoc: ${err.message.slice(0, 60)}`;
      }
    }
    if (r.body && s.extract === "markdown-json-fence") {
      // One page may hold one OpenAPI document per endpoint (Adyntel): those with paths are merged into the
      // first, so the entry covers the page. A page with a single fence is taken as it is.
      const fences = [...r.body.matchAll(/```json\s*\n([\s\S]*?)\n```/g)].map((m) => m[1]);
      const specFences = fences.filter((f) => {
        try {
          const d = JSON.parse(f);
          return Boolean((d?.openapi || d?.swagger) && d.paths && Object.keys(d.paths).length);
        } catch {
          return false;
        }
      });
      const docs = specFences.map((f) => JSON.parse(f));
      // A fence holding only shared components (no paths) is merged too, so $refs into it resolve.
      // A fence holding only shared components (an OpenAPI root, no paths) is merged too, so $refs into it resolve.
      const componentDocs = fences
        .filter((f) => !specFences.includes(f))
        .map((f) => { try { return JSON.parse(f); } catch { return null; } })
        .filter((d) => (d?.openapi || d?.swagger) && d.components && !Object.keys(d.paths ?? {}).length);
      const conflicts = [];
      if (docs.length > 1 || (docs.length === 1 && componentDocs.length)) {
        // Merged only where nothing can be lost: the documents agree on version, servers and security, a path
        // appears in one document (or identically in several), and a component name means one thing.
        // Anything else fails the spec rather than publishing a merge that misdescribes an endpoint.
        const [first, ...rest] = docs;
        // Servers and security apply to operations, so only the documents with paths must agree on them.
        const same = (k, ds) => new Set(ds.map((d) => canonical(d[k] ?? null))).size === 1;
        for (const k of ["openapi", "swagger"]) if (!same(k, [...docs, ...componentDocs])) conflicts.push(`top-level ${k}`);
        for (const k of ["servers", "security"]) if (!same(k, docs)) conflicts.push(`top-level ${k}`);
        const METHODS = new Set(["get", "put", "post", "delete", "options", "head", "patch", "trace", "query"]);
        const rest_ = (item) => Object.fromEntries(Object.entries(item ?? {}).filter(([m]) => !METHODS.has(m)));
        for (const d of rest) for (const t of d.tags ?? []) if (!(first.tags ??= []).some((x) => x.name === t.name)) first.tags.push(t);
        for (const d of [...rest, ...componentDocs]) {
          for (const [k, v] of Object.entries(d.paths ?? {})) {
            // One path in two documents (GET in one, POST in another): merged method by method when the
            // rest of the path item (parameters, servers, $ref, extensions) is identical.
            const have = first.paths[k];
            if (have === undefined) first.paths[k] = v;
            else if (canonical(rest_(have)) !== canonical(rest_(v))) conflicts.push(`path ${k}`);
            else
              for (const [m, op] of Object.entries(v ?? {})) {
                if (!METHODS.has(m)) continue;
                if (have[m] === undefined) have[m] = op;
                else if (canonical(have[m]) !== canonical(op)) conflicts.push(`${m} ${k}`);
              }
          }
          for (const [kind, defs] of Object.entries(d.components ?? {})) {
            first.components ??= {};
            first.components[kind] ??= {};
            for (const [name, def] of Object.entries(defs ?? {})) {
              const have = first.components[kind][name];
              if (have === undefined) first.components[kind][name] = def;
              else if (canonical(have) !== canonical(def)) conflicts.push(`${kind}.${name}`);
            }
          }
        }
        r.body = JSON.stringify(first);
        if (conflicts.length) {
          r.body = null;
          r.error = `fences define ${conflicts.slice(0, 3).join(", ")} differently`;
        }
      } else r.body = specFences[0] ?? fences[0] ?? null; // one document: its own text, byte for byte
      if (!fences.length) r.error = "no json fence found";
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
      specs[s.name] = { ...withoutCoverage(old), ...(s.coverage ? { coverage: s.coverage } : {}), status: r.error ?? `HTTP ${r.status}` };
      console.log(`✗ ${e.id} · ${s.name}: ${specs[s.name].status}${newlyFailing(old) ? " (newly failing)" : ""}`);
      continue;
    }
    let info;
    try {
      if (bundle) {
        // One entry per module file; the bundle's count is their sum.
        // A repository archive also holds JSON schemas, configs and examples: keep the files that are specs
        // of the declared format, and fail only when none is.
        const parts = [];
        const skipped = [];
        const specFiles = [];
        for (const f of bundle) {
          try {
            parts.push(inspect(s.format, f.text));
            specFiles.push(f);
          } catch (err) {
            // Not a spec of the declared format (a schema, a config), or a spec that doesn't parse: say which.
            skipped.push(`${f.name.replace(/^[^/]*\//, "")}: ${String(err.message).slice(0, 60)}`);
          }
        }
        bundle = specFiles; // hash and size only what was counted, so a changed README isn't "drift"
        if (!parts.length) throw new Error(`no ${s.format} file among ${bundle.length} in the bundle`);
        const one = (k) => [...new Set(parts.map((x) => x[k]).filter(Boolean))];
        const versions = one("apiVersion");
        info = {
          operations: parts.reduce((n, x) => n + (x.operations ?? 0), 0),
          files: parts.length,
          ...(skipped.length ? { skippedFiles: skipped.length, skipped: skipped.slice(0, 20) } : {}),
          // Each module has its own title; the bundle is named by the entry, with the module count beside it.
          title: s.name,
          apiVersion: versions.length === 1 ? versions[0] : versions.join(", ") || null,
          specVersion: parts[0]?.specVersion,
          // Every module's version, so the format check covers all of them, not just the first.
          specVersions: [...new Set(parts.map((x) => x.specVersion).filter(Boolean))],
          // Missing required fields in any module, so the nightly PR flags them for bundles too.
          ...(parts.some((x) => x.specIssues)
            ? (() => {
                const issues = parts.map((x, i) => (x.specIssues ? `${specFiles[i].name.replace(/^[^/]*\//, "")}: ${x.specIssues}` : null)).filter(Boolean);
                return { specIssues: `${issues.length} of ${parts.length} modules: ${issues.slice(0, 10).join("; ")}${issues.length > 10 ? "; …" : ""}` };
              })()
            : {}),
          server: parts.find((x) => x.server)?.server,
          // One fingerprint for the bundle: every module's, in file order.
          // By base name, as sha256 is: a rebuilt archive may list or nest the same files differently.
          ...(parts.some((x) => x.surface)
            ? { surface: createHash("sha256").update(parts.map((x, i) => [specFiles[i].name.replace(/^.*\//, ""), x.surface ?? "-", specFiles[i].name]).sort((a, b) => a[0].localeCompare(b[0]) || a[2].localeCompare(b[2])).map((x) => `${x[0]}=${x[1]}`).join(",")).digest("hex").slice(0, 16) }
            : {}),
          ...(parts.some((x) => x.suspicious)
            ? { suspicious: parts.flatMap((x) => x.suspicious ?? []).slice(0, 3), suspiciousSha: suspiciousFingerprint(parts.flatMap((x, i) => (x.suspiciousSha ? [`${specFiles[i].name.replace(/^.*\//, "")}=${x.suspiciousSha}`] : []))) }
            : {}),
        };
      } else info = inspect(s.format, r.body);
    } catch (err) {
      failures++;
      specs[s.name] = { ...withoutCoverage(old), ...(s.coverage ? { coverage: s.coverage } : {}), status: `unparseable: ${err.message.slice(0, 80)}` };
      console.log(`✗ ${e.id} · ${s.name}: unparseable${newlyFailing(old) ? " (newly failing)" : ""}`);
      continue;
    }
    // Google Discovery docs come back with a different key order on each request and re-stamp etag and
    // revision on every publish, with no change to the API. Hash a key-sorted copy without those fields,
    // or the nightly job would open a drift PR every night.
    const { doc, introspection, ...meta } = info;
    info = meta;
    // A GraphQL SDL spec's introspection result, published for consumers; rewritten only when it changes.
    if (introspection) {
      // Named after the spec's URL, so connectors sharing a schema (linear, linear-multiworkspace) share a file.
      const file = `derived/graphql/${createHash("sha256").update(s.url ?? s.path).digest("hex").slice(0, 16)}.introspection.json`;
      // Indented like index.json, so a vendor's schema change reads as a line diff in the nightly PR.
      const text = JSON.stringify(introspection, null, 2) + "\n";
      const abs = join(ROOT, file);
      if (!existsSync(abs) || readFileSync(abs, "utf8") !== text) {
        mkdirSync(dirname(abs), { recursive: true });
        writeFileSync(abs, text);
      }
      info.derived = { file, sha256: createHash("sha256").update(text).digest("hex"), bytes: Buffer.byteLength(text) };
    } else if (info.derivedError && old.derived) {
      // graphql-js stopped accepting the vendor's SDL: keep the last good introspection result, flagged.
      info.derived = old.derived;
    }
    // The entry's server is set by hand and wins; specs often carry placeholders (DefaultParameterValue,
    // {baseUrl}). The spec's own value is kept as specServer when they differ.
    if (s.server && info.server && info.server !== s.server) info.specServer = info.server;
    // The entry's format must match the document: a 3.1 spec declared openapi-3.0 picks the wrong parser downstream.
    // openapi-3.1 also covers 3.2, a backwards-compatible minor version (Shopware publishes 3.2).
    const accepts = { "openapi-3.0": ["3.0"], "openapi-3.1": ["3.1", "3.2"], "swagger-2.0": ["2.0"], "postman-2.0": ["2.0"], "postman-2.1": ["2.1"] }[s.format];
    const versions = info.specVersions ?? (info.specVersion ? [info.specVersion] : []);
    const wrong = versions.filter((ver) => !accepts?.some((v) => String(ver).startsWith(v)));
    if (accepts && wrong.length) info.formatMismatch = `declared ${s.format}, the spec says ${wrong.join(", ")}`;
    delete info.specVersions;
    if (s.server) info.server = s.server;
    // A rebuilt zip changes its bytes (timestamps, compression) without any spec changing, so a bundle
    // is hashed on its files' names and contents.
    // A spec carrying a generated date (see withoutGeneratedDates) is hashed on a parsed, key-sorted copy;
    // every other file on its exact bytes, as before.
    const generatedDates = !doc && !bundle && OVERLAY_FORMATS.has(s.format) && GENERATED_DATE_DEFAULT.test(r.body);
    let parsedForHash = null;
    if (generatedDates) {
      try {
        parsedForHash = /^\s*[{[]/.test(r.body) ? JSON.parse(r.body) : parseYaml(r.body, { maxAliasCount: 10000 });
      } catch {
        parsedForHash = null; // unparseable here: fall back to the raw bytes
      }
    }
    const hashed = doc
      ? canonical(withoutGeneratedDates({ ...doc, etag: undefined, revision: undefined }))
      : bundle
        ? canonical([...bundle].sort((a, b) => a.name.localeCompare(b.name)).map((f) => [f.name.replace(/^.*\//, ""), f.text]))
        : parsedForHash
          ? canonical(withoutGeneratedDates(parsedForHash))
          : r.body;
    const sha256 = createHash("sha256").update(hashed).digest("hex");
    // Only where the served bytes are stable: a Discovery document, a zip bundle, a spec with generated dates
    // and an extracted spec are hashed in a normalised form (sha256), since their bytes differ between
    // requests or carry page build hashes; a raw hash would change every night.
    const fetchSha256 = r.fetchSha256 && !doc && !bundle && !parsedForHash && !s.extract ? r.fetchSha256 : undefined;
    // A changed fetchSha256 is a change too (a byte-order mark added, say): consumers check against it.
    const changed = (old.sha256 && old.sha256 !== sha256) || Boolean(old.fetchSha256 && fetchSha256 && old.fetchSha256 !== fetchSha256);
    // An overlay is applied to the fetched spec on every run. Its actions whose target no longer matches
    // anything are listed: the vendor fixed the mistake (drop the action) or moved it (update the target).
    let overlay;
    if (s.overlay) {
      const text = readFileSync(join(ROOT, s.overlay), "utf8");
      try {
        const parseSpec = () => (/^\s*[{[]/.test(r.body) ? JSON.parse(r.body) : parseYaml(r.body, { maxAliasCount: 10000 }));
        const overlaySet = parseYaml(text);
        // Applied one action at a time, so each is judged on its own effect: an action whose target matches
        // nothing is unmatched (the vendor moved it), an update that leaves its target unchanged is
        // redundant (the vendor already says it: they fixed it).
        let current = parseSpec();
        const unmatched = [];
        const redundant = [];
        for (const action of overlaySet.actions) {
          const before = canonical(resolveJsonPathValue(current, action.target));
          const res = await openapiOverlay(current, { overlaySet: { ...overlaySet, actions: [action] } });
          if (res.resultData.unusedActions.length) unmatched.push(action.target);
          else if (action.update !== undefined && before === canonical(resolveJsonPathValue(res.data, action.target))) redundant.push(action.target);
          current = res.data;
        }
        overlay = {
          file: s.overlay,
          sha256: createHash("sha256").update(text).digest("hex"),
          actions: overlaySet.actions.length,
          ...(unmatched.length ? { unmatched } : {}),
          ...(redundant.length ? { redundant } : {}),
        };
      } catch (err) {
        overlay = { file: s.overlay, error: err.message.slice(0, 120) };
      }
    }
    // Servers or authentication differ from the last check: flagged, and the nightly PR waits for a person.
    const surfaceChanged = Boolean(old.surface && info.surface && old.surface !== info.surface);
    // Flagged text is recorded (suspicious); it holds the nightly PR only when it differs from what was
    // recorded, and so reviewed, before. OpenAI's docs mention its own <|endoftext|> token, for one.
    const suspiciousNew = Boolean(info.suspiciousSha) && info.suspiciousSha !== old.suspiciousSha;
    // A spec seen for the first time has no earlier fingerprint to compare: its servers and auth are new.
    const surfaceNew = Boolean(info.surface && !old.surface);
    specs[s.name] = {
      status: "ok",
      sha256,
      ...(fetchSha256 ? { fetchSha256 } : {}),
      // For a bundle, the size of its files: the archive's own size changes when it is merely rebuilt.
      bytes: bundle ? bundle.reduce((n, f) => n + Buffer.byteLength(f.text), 0) : Buffer.byteLength(r.body),
      ...Object.fromEntries(Object.entries(info).filter(([, v]) => v != null)),
      changedOn: changed || !old.sha256 ? today : old.changedOn,
      ...(surfaceChanged ? { surfaceChangedOn: today } : old.surfaceChangedOn && info.surface === old.surface ? { surfaceChangedOn: old.surfaceChangedOn } : {}),
      ...(overlay ? { overlay } : {}),
      ...(s.coverage ? { coverage: s.coverage } : {}),
    };
    // Δ changed, + newly indexed, ↺ recovered from a failure, ✓ unchanged. The nightly PR body lists all but ✓.
    const mark = changed ? "Δ" : !old.sha256 ? "+" : old.status && old.status !== "ok" ? "↺" : "✓";
    const problems = overlay?.error
      ? [overlay.error]
      : [overlay?.unmatched?.length && `${overlay.unmatched.length} action(s) match nothing`, overlay?.redundant?.length && `${overlay.redundant.length} action(s) change nothing`].filter(Boolean);
    const stale =
      (problems.length ? ` ⚠ overlay: ${problems.join("; ")}` : "") +
      (info.derivedError ? ` ⚠ SDL not parseable by graphql-js (${info.derivedError})${info.derived ? "; kept the last introspection result" : ""}` : "") +
      (info.formatMismatch ? ` ⚠ format: ${info.formatMismatch}` : "") +
      (info.specIssues ? ` ⚠ spec: ${info.specIssues}` : "") +
      (surfaceChanged ? " ⚠ surface: servers or authentication changed" : "") +
      (surfaceNew ? " ⚠ surface: first check of its servers and authentication" : "") +
      (suspiciousNew ? ` ⚠ text: reads like instructions to an AI (${info.suspicious.map((x) => JSON.stringify(x)).join("; ")})` : "");
    console.log(`${mark} ${e.id} · ${s.name}: ${info.operations ?? "?"} operations${stale}`);
  }
  out.connectors[e.id] = { name: e.name, ...(e.apideck === false ? { apideck: false } : {}), specs };
}
// Entries removed from connectors/ leave the index too.
for (const id of Object.keys(out.connectors)) if (!entries.some((e) => e.id === id)) delete out.connectors[id];

// Derived files nothing in the index points at any more (a spec moved, an entry left) are removed. Only on a
// full run: a run with --only can't see the other entries' files.
if (!ONLY && existsSync(join(ROOT, "derived/graphql"))) {
  const used = new Set(Object.values(out.connectors).flatMap((c) => Object.values(c.specs).map((s) => s.derived?.file)).filter(Boolean));
  for (const f of readdirSync(join(ROOT, "derived/graphql")).filter((n) => n.endsWith(".introspection.json"))) {
    if (!used.has(`derived/graphql/${f}`)) {
      unlinkSync(join(ROOT, "derived/graphql", f));
      console.log(`- derived/graphql/${f}: no spec uses it any more, removed`);
    }
  }
}

writeFileSync(indexPath, JSON.stringify(out, null, 2) + "\n");
console.log(`\nindex.json written; ${failures} spec(s) failed to fetch or parse.`);
