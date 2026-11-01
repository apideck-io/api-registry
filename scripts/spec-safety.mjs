// Two checks on a spec's content, both recorded in index.json and flagged (⚠) in the nightly PR:
//
// surface   A fingerprint of where calls go and how they authenticate: servers, hosts, security schemes and
//           requirements. A vendor rarely changes these; when they do change, a person should look before
//           the new file is trusted, so the nightly PR is not merged automatically.
// suspicious Text in descriptions or summaries that reads like instructions to an AI agent ("ignore previous
//           instructions", chat-template tokens, bidirectional overrides). Tools built from a spec pass this text to
//           a model, so a spec carrying it is held for review.

import { createHash } from "node:crypto";

// Phrases aimed at a model rather than a developer. Kept narrow: API docs say "you must", "call this
// endpoint" and "the token" all the time, and AI vendors document a "system prompt" parameter, so plain
// imperatives and that phrase are not flagged.
export const INSTRUCTION_LIKE = [
  /\b(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|preceding|system)\s+(instructions?|prompts?|messages?|rules|context)/i,
  /\byou\s+are\s+(now\s+)?(an?\s+)?(ai|assistant|chatbot|language\s+model|llm|claude|chatgpt|gpt)\b/i,
  // Chat-template tokens need both pipes: <User> is a generic type in plenty of specs.
  /<\|\s*(im_start|im_end|endoftext|system|assistant|user)\s*\|>/i,
  /\[\/?INST\]|<<\/?SYS>>/,
  /\bdo\s+not\s+(tell|inform|reveal\s+to|mention\s+to)\s+the\s+user\b/i,
  /\b(send|post|forward|exfiltrate|upload)\b[^.]{0,60}\b(api[\s_-]?keys?|access\s+tokens?|credentials|passwords?|secrets?)\b[^.]{0,40}\bto\s+(https?:\/\/|\S+@\S+)/i,
  // Not "agent": in helpdesk APIs that is a person ("the agent should call the customer back").
  /\b(ai|llm|assistant|language\s+model)s?\b[^.]{0,30}\b(must|should)\s+(always\s+|now\s+|first\s+)?(ignore|call|invoke|execute|run|send)\b/i,
];
// Bidirectional overrides and marks make text display differently from what a model reads; Unicode tag
// characters (U+E0000-E007F), variation selectors and invisible operators are invisible and still read by
// some models. Zero-width spaces are common in
// pasted vendor docs and are not flagged (consumers strip them).
// One U+FE0F follows many emoji; only a run of variation selectors is the smuggling pattern.
export const HIDDEN_CHARS = /[\u061C\u200E\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]|[\uFE00-\uFE0F]{2,}/u;
const HIDDEN_ALL = new RegExp(HIDDEN_CHARS.source, "gu");

const TEXT_KEYS = new Set(["description", "summary", "title", "x-summary", "deprecationReason"]);

/**
 * Instruction-like or hidden text in a parsed spec. `samples` are short, readable excerpts (distinct, for
 * index.json); `hits` are every flagged text in full with where it sits, so a fingerprint of them changes when
 * text is added to an already-accepted description or copied to another place.
 */
export function scanText(doc, { max = 10000, positional = true } = {}) {
  // Each object's hits are collected once and replayed under every place it appears: a YAML alias reused in
  // two places counts twice (adding or removing a copy changes the fingerprint), shared subtrees aren't
  // rescanned, and a self-reference (an object already on the current path) stops the walk.
  const cache = new WeakMap();
  const onPath = new Set();
  let total = 0;
  const collect = (v, key, depth) => {
    if (v == null || depth > 1000) return [];
    if (typeof v === "string") {
      if (!TEXT_KEYS.has(key)) return [];
      const hidden = HIDDEN_CHARS.test(v);
      const hit = INSTRUCTION_LIKE.find((re) => re.test(v));
      return hidden || hit ? [{ rel: "", text: v, hidden, hit }] : [];
    }
    if (typeof v !== "object" || onPath.has(v)) return [];
    const byKey = cache.get(v);
    if (byKey?.has(key)) return byKey.get(key);
    onPath.add(v);
    const out = [];
    // A list position isn't part of the place: a type or parameter added earlier would shift every later one.
    if (Array.isArray(v)) for (const x of v) for (const h of collect(x, key, depth + 1)) out.length < max && out.push({ ...h, rel: `/*${h.rel}` });
    // A Postman description can be an object: { content, type }.
    else
      for (const [k, x] of Object.entries(v))
        for (const h of collect(x, TEXT_KEYS.has(key) && k === "content" ? key : k, depth + 1)) out.length < max && out.push({ ...h, rel: `/${k}${h.rel}` });
    onPath.delete(v);
    if (!cache.has(v)) cache.set(v, new Map());
    cache.get(v).set(key, out);
    total += out.length;
    return out;
  };
  const found = collect(doc, "", 0).slice(0, max);
  const hits = found.map((h) => `${positional ? h.rel : ""}\u0000${h.text}`);
  const samples = [];
  for (const h of found) {
    const i = h.hit ? h.text.search(h.hit) : h.text.search(HIDDEN_CHARS);
    const sample = (h.hidden ? "hidden characters: " : "") + h.text.slice(Math.max(0, i - 20), i + 60).replace(/\s+/g, " ").replace(HIDDEN_ALL, "\u2423");
    if (!samples.includes(sample)) samples.push(sample);
    if (samples.length >= 3) break;
  }
  return { samples, hits };
}

/** Descriptions in a GraphQL SDL file (block and plain strings), as a document scanText can scan. Scan it with
 * positional: false, since a new string earlier in the file would shift every later one. */
export function sdlDescriptions(sdl) {
  return { description: [...sdl.matchAll(/"""([\s\S]*?)"""|"((?:[^"\\\n]|\\.)*)"/g)].map((m) => m[1] ?? m[2]) };
}

/** A short, order-independent fingerprint of every flagged text and its place. */
export function suspiciousFingerprint(hits) {
  return hits.length ? createHash("sha256").update(JSON.stringify([...hits].sort())).digest("hex").slice(0, 16) : null;
}

// Cycle-safe: a YAML anchor can refer back to itself inside servers or security schemes.
const canonical = (v, stack = new Set()) => {
  if (!v || typeof v !== "object") return JSON.stringify(v);
  if (stack.has(v)) return '"[cycle]"';
  stack.add(v);
  const out = Array.isArray(v)
    ? `[${v.map((x) => canonical(x, stack)).join(",")}]`
    : `{${Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k], stack)}`).join(",")}}`;
  stack.delete(v);
  return out;
};

const METHODS = ["get", "put", "post", "delete", "options", "head", "patch", "trace", "query"];
// Scope order in a security requirement means nothing, and some vendors (X) shuffle it on every request.
// The requirements in the list are alternatives, so their order means nothing either.
const security = (reqs) =>
  Array.isArray(reqs)
    ? reqs.map((r) => Object.fromEntries(Object.entries(r ?? {}).map(([k, v]) => [k, Array.isArray(v) ? [...v].sort() : v]))).sort((a, b) => canonical(a).localeCompare(canonical(b)))
    : (reqs ?? null);
// Tuples collected per path are sorted, so reordering paths in the file doesn't change the fingerprint.
const sorted = (rows) => rows.sort((a, b) => canonical(a).localeCompare(canonical(b)));

/** A short hash of where a spec's calls go and how they authenticate, or null for formats without one. */
export function surfaceOf(format, doc) {
  let surface = null;
  if (format.startsWith("openapi-")) {
    const perPath = [];
    // OpenAPI 3.1 path items can be references into components.pathItems.
    // Followed up to ten hops; a reference that can't be resolved here (another file) is kept as its target,
    // so changing where it points changes the fingerprint.
    const deref = (item) => {
      let cur = item;
      for (let hop = 0; hop < 10 && typeof cur?.$ref === "string"; hop++) {
        const ref = /^#\/components\/pathItems\/(.+)$/.exec(cur.$ref)?.[1];
        if (!ref) break;
        let name = ref.replace(/~1/g, "/").replace(/~0/g, "~");
        try {
          name = decodeURIComponent(name);
        } catch {
          // a malformed escape: look it up as written
        }
        const target = doc.components?.pathItems?.[name];
        if (!target || typeof target !== "object") break;
        const { $ref: _ref, ...rest } = cur;
        cur = { ...target, ...rest };
      }
      return cur;
    };
    // Webhooks (OpenAPI 3.1) are operations too, with their own servers and security.
    for (const [p, raw] of [...Object.entries(doc.paths ?? {}), ...Object.entries(doc.webhooks ?? {}).map(([k, v]) => [`webhook:${k}`, v])]) {
      const item = deref(raw);
      if (!item || typeof item !== "object") continue;
      if (typeof item.$ref === "string") perPath.push([p, "$ref", item.$ref]);
      if (item.servers) perPath.push([p, "*", item.servers]);
      for (const m of METHODS) {
        const op = item[m];
        if (op?.servers) perPath.push([p, m, op.servers]);
        if (op?.security) perPath.push([p, m, "security", security(op.security)]);
      }
    }
    surface = { servers: doc.servers ?? null, schemes: doc.components?.securitySchemes ?? null, security: security(doc.security), perPath: sorted(perPath) };
  } else if (format === "swagger-2.0") {
    const perOp = [];
    // An operation's own schemes override the document's (an http-only operation).
    for (const [p, item] of Object.entries(doc.paths ?? {}))
      for (const m of METHODS) {
        if (item?.[m]?.security) perOp.push([p, m, security(item[m].security)]);
        if (item?.[m]?.schemes) perOp.push([p, m, "schemes", item[m].schemes]);
      }
    surface = { host: doc.host ?? null, parameterizedHost: doc["x-ms-parameterized-host"] ?? null, basePath: doc.basePath ?? null, schemes: doc.schemes ?? null, definitions: doc.securityDefinitions ?? null, security: security(doc.security), perOp: sorted(perOp) };
  } else if (format === "asyncapi-2") {
    // Brokers and how clients authenticate to them.
    surface = { servers: doc.servers ?? null, schemes: doc.components?.securitySchemes ?? null };
  } else if (format === "google-discovery") {
    surface = {
      rootUrl: doc.rootUrl ?? null,
      servicePath: doc.servicePath ?? null,
      baseUrl: doc.baseUrl ?? null,
      mtlsRootUrl: doc.mtlsRootUrl ?? null,
      batchPath: doc.batchPath ?? null,
      endpoints: doc.endpoints ?? null,
      auth: doc.auth ?? null,
    };
  } else if (format.startsWith("postman-")) {
    const hosts = new Set();
    const auth = [];
    const scripts = [];
    const seenItems = new WeakSet();
    const vars = [...(Array.isArray(doc.variable) ? doc.variable : [])];
    // Pre-request and test scripts can send requests (pm.sendRequest) anywhere, credentials included.
    const events = (at, ev) => (Array.isArray(ev) ? ev : []).forEach((e) => e?.script && scripts.push([at, e.listen ?? null, e.script.exec ?? null]));
    events("", doc.event);
    const walk = (items, at) =>
      (Array.isArray(items) ? items : []).forEach((it, i) => {
        if (!it || typeof it !== "object" || seenItems.has(it)) return;
        seenItems.add(it);
        const here = `${at}/${it.name ?? i}`;
        events(here, it.event);
        // A request can be written as just its URL.
        const u = typeof it.request === "string" ? it.request : it.request?.url;
        // Scheme and host, from the raw URL and from the structured fields Postman actually sends: a switch
        // from https to http sends credentials in cleartext.
        if (typeof u === "string" || u?.raw) {
          // The scheme can be a variable too ({{scheme}}://{{host}}).
          const m = /^((?:[a-z][\w+.-]*|\{\{[^}]+\}\}):\/\/)?([^/?#]*)/i.exec(String(typeof u === "string" ? u : u.raw));
          hosts.add(`${(m[1] ?? "").toLowerCase()}${m[2]}`);
        }
        if (u && typeof u === "object" && (u.host || u.protocol || u.port)) {
          const host = Array.isArray(u.host) ? u.host.join(".") : u.host ?? "";
          hosts.add(`${u.protocol ? `${String(u.protocol).toLowerCase()}://` : ""}${host}${u.port ? `:${u.port}` : ""}`);
        }
        // Folder-level variables count like the collection's.
        if (Array.isArray(it.variable)) vars.push(...it.variable);
        // Auth set on a folder or a request overrides the collection's.
        if (it.auth) auth.push([here, it.auth]);
        if (it.request?.auth) auth.push([`${here}#request`, it.request.auth]);
        walk(it.item, here);
      });
    walk(doc.item, "");
    // A host is usually {{baseUrl}}, and an OAuth block's token URL {{auth_url}}: the collection variables
    // these name are where calls and credentials actually go. Other variables (sample ids, dates) aren't.
    const refs = (text) => [...String(text).matchAll(/\{\{\s*([^}\s]+)\s*\}\}/g)].map((m) => m[1]);
    const used = new Set([...[...hosts].flatMap(refs), ...refs(canonical([doc.auth ?? null, auth]))]);
    // Followed through other variables: baseUrl = {{scheme}}://{{host}} makes host count too.
    for (let grew = true; grew; ) {
      grew = false;
      for (const v of vars) if (used.has(v?.key ?? v?.id)) for (const r of refs(v?.value ?? "")) if (!used.has(r)) (used.add(r), (grew = true));
    }
    const variables = vars.filter((v) => v && used.has(v.key ?? v.id)).map((v) => [v.key ?? v.id, v.value ?? null]).sort((a, b) => String(a[0]).localeCompare(String(b[0])) || canonical(a[1]).localeCompare(canonical(b[1])));
    surface = { auth: doc.auth ?? null, nested: auth, hosts: [...hosts].sort(), variables, scripts };
  }
  return surface && createHash("sha256").update(canonical(surface)).digest("hex").slice(0, 16);
}
