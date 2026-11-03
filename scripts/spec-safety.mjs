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
  // Each object's result is computed once and replayed under every place it appears: a YAML alias reused in
  // two places counts twice (adding or removing a copy changes the fingerprint), shared subtrees aren't
  // rescanned, and a self-reference (an object already on the current path) stops the walk. Each result keeps
  // an exact count of its hits but at most `max` of them, so a document with a huge number of matches (an
  // alias bomb) stays cheap, and a hit beyond the cap still changes the fingerprint through the count.
  const cache = new WeakMap();
  const onPath = new Set();
  const add = (out, h, prefix) => {
    if (out.hits.length < max) out.hits.push({ ...h, rel: `${prefix}${h.rel}` });
  };
  const collect = (v, key, depth) => {
    if (v == null || depth > 1000) return { hits: [], count: 0 };
    if (typeof v === "string") {
      if (!TEXT_KEYS.has(key)) return { hits: [], count: 0 };
      const hidden = HIDDEN_CHARS.test(v);
      const hit = INSTRUCTION_LIKE.find((re) => re.test(v));
      return hidden || hit ? { hits: [{ rel: "", text: v, hidden, hit }], count: 1 } : { hits: [], count: 0 };
    }
    if (typeof v !== "object" || onPath.has(v)) return { hits: [], count: 0 };
    const byKey = cache.get(v);
    if (byKey?.has(key)) return byKey.get(key);
    onPath.add(v);
    const out = { hits: [], count: 0 };
    // A list position isn't part of the place: a type or parameter added earlier would shift every later one.
    const children = Array.isArray(v)
      ? v.map((x) => [x, key, "/*"])
      : // A Postman description can be an object: { content, type }.
        Object.entries(v).map(([k, x]) => [x, TEXT_KEYS.has(key) && k === "content" ? key : k, `/${k}`]);
    for (const [x, k, prefix] of children) {
      const r = collect(x, k, depth + 1);
      out.count += r.count;
      for (const h of r.hits) {
        if (out.hits.length >= max) break;
        add(out, h, prefix);
      }
    }
    onPath.delete(v);
    if (!cache.has(v)) cache.set(v, new Map());
    cache.get(v).set(key, out);
    return out;
  };
  const { hits: found, count } = collect(doc, "", 0);
  const hits = found.map((h) => `${positional ? h.rel : ""}\u0000${h.text}`);
  if (count > found.length) hits.push(`\u0000[${count} matches in all]`);
  const samples = [];
  for (const h of found) {
    const i = h.hit ? h.text.search(h.hit) : h.text.search(HIDDEN_CHARS);
    const sample = (h.hidden ? "hidden characters: " : "") + h.text.slice(Math.max(0, i - 20), i + 60).replace(/\s+/g, " ").replace(HIDDEN_ALL, "\u2423");
    if (!samples.includes(sample)) samples.push(sample);
    if (samples.length >= 3) break;
  }
  return { samples, hits };
}

/** The text in an XML document (element text and attribute values), each as its own description. */
export function xmlTexts(xml) {
  const decode = (t) => t.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, "&");
  const texts = [
    ...[...xml.matchAll(/>([^<]+)</g)].map((m) => m[1]),
    ...[...xml.matchAll(/=\s*"([^"]*)"/g)].map((m) => m[1]),
    ...[...xml.matchAll(/=\s*'([^']*)'/g)].map((m) => m[1]),
  ]
    .map((t) => decode(t).trim())
    .filter((t) => t.length >= 12);
  return { description: texts };
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
// Repeating a requirement doesn't change what's required, so repeats don't count (XTRF serves a varying number).
const unique = (rows) => [...new Map(rows.map((r) => [canonical(r), r])).values()];
const security = (reqs) =>
  Array.isArray(reqs)
    ? unique(reqs.map((r) => Object.fromEntries(Object.entries(r ?? {}).map(([k, v]) => [k, Array.isArray(v) ? [...v].sort() : v])))).sort((a, b) => canonical(a).localeCompare(canonical(b)))
    : (reqs ?? null);
// Tuples collected per path are sorted, so reordering paths in the file doesn't change the fingerprint.
const sorted = (rows) => rows.sort((a, b) => canonical(a).localeCompare(canonical(b)));

// A nonce in an authorization URL is generated per request (Avalara), so it isn't part of where calls go.
// Only there: a changed token or server URL always counts.
// A YAML anchor can refer back to itself here. Each object is cloned once, and a reference back to it points to
// the clone, so canonical still sees the cycle and every copy has its nonce blanked.
const withoutAuthNonce = (v, key, seen = new WeakMap()) => {
  if (key === "authorizationUrl" && typeof v === "string") return v.replace(/([?&]nonce=)[^&#]*/g, "$1");
  if (!v || typeof v !== "object") return v;
  if (seen.has(v)) return seen.get(v);
  // No prototype, so a key named __proto__ is kept as an ordinary key, as YAML and JSON parsers keep it.
  const out = Array.isArray(v) ? [] : Object.create(null);
  seen.set(v, out);
  for (const [k, x] of Object.entries(v)) out[k] = withoutAuthNonce(x, Array.isArray(v) ? undefined : k, seen);
  return out;
};

/** Where a spec's calls go and how they authenticate, as a canonical object (before hashing), or null for
 *  formats without one. */
export function surfaceDetail(format, doc) {
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
    // A channel can pin the servers it is on, and each publish/subscribe operation its own security.
    const channels = Object.entries(doc.channels ?? {})
      .map(([name, c]) => [name, c?.servers ?? null, security(c?.publish?.security), security(c?.subscribe?.security)])
      .filter((row) => row.slice(1).some((x) => x != null));
    surface = { servers: doc.servers ?? null, schemes: doc.components?.securitySchemes ?? null, channels: sorted(channels) };
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
  return surface && withoutAuthNonce(surface);
}

/** The fingerprint of surfaceDetail: what the index stores, and compares night to night. */
export function surfaceOf(format, doc) {
  const detail = surfaceDetail(format, doc);
  return detail && surfaceHash(detail);
}

export const surfaceHash = (detail) => createHash("sha256").update(canonical(detail)).digest("hex").slice(0, 16);

// The surface as sorted text rows, one per server, scheme, requirement or per-operation override, so two nights
// can be compared row by row and a reviewer sees what changed ("servers[0]: …"), not only that the fingerprint
// moved. A list of plain values is one row; a list of objects one row per item, with its position (which server
// comes first is the default, so order counts, as it does in the fingerprint); a list of tuples one row each.
// Vendor text is escaped: a name with a line break must not start a line of its own in the nightly PR body.
const esc = (t) => JSON.stringify(String(t)).slice(1, -1);
// Characters a reviewer can't see, or that reorder what they see (bidi overrides, invisible tags, line separators),
// are shown escaped, so a row can't display a different host or scheme than the one in the spec.
const visible = (row) =>
  row.replace(/[\u0000-\u001f\u007f-\u009f\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u200b-\u200f\u2028-\u202e\u2060-\u2064\u2066-\u2069\u3164\ufe00-\ufe0f\ufeff\uffa0]|[\u{e0000}-\u{e007f}]/gu, (c) => `\\u{${c.codePointAt(0).toString(16)}}`);
const key = (k) => (/^[A-Za-z0-9_$-]+$/.test(k) ? k : `[${JSON.stringify(k)}]`);
export function surfaceRows(detail) {
  const rows = [];
  const walk = (v, at, stack) => {
    if (v === null || typeof v !== "object") return rows.push(`${at}: ${JSON.stringify(v)}`);
    if (stack.has(v)) return rows.push(`${at}: [cycle]`);
    if (Array.isArray(v)) {
      if (v.every((x) => x === null || typeof x !== "object")) return rows.push(`${at}: ${canonical(v)}`);
      // A per-operation tuple (path, method, what, value) reads as words: "/v2/notes post security [...]".
      v.forEach((x, i) =>
        rows.push(
          Array.isArray(x)
            ? `${at}: ${x.map((p) => (typeof p !== "string" ? canonical(p) : /\s/.test(p) || /^(null|true|false|-?\d)/.test(p) ? JSON.stringify(p) : esc(p))).join(" ")}`
            : // A server list is ordered (the first is the default); other lists (security requirements) are
              // sorted sets, where a position would make one new entry re-number every one after it.
              /(^|\.)servers$/.test(at)
              ? `${at}[${i}]: ${canonical(x)}`
              : `${at}[]: ${canonical(x)}`,
        ),
      );
      return;
    }
    const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
    if (!keys.length) return rows.push(`${at}: {}`);
    stack.add(v);
    for (const k of keys) walk(v[k], at ? `${at}.${key(k)}` : key(k), stack);
    stack.delete(v);
  };
  walk(detail, "", new Set());
  return [...new Set(rows.map(visible))].sort();
}

/** The rows that went and came between two nights, "- " and "+ ", at most max of them (shared between the two,
 *  so additions aren't hidden behind removals), long rows cut. */
export function surfaceDiff(before, after, max = 15) {
  const was = new Set(before), now = new Set(after);
  const gone = before.filter((r) => !now.has(r)).map((r) => `- ${r}`);
  const came = after.filter((r) => !was.has(r)).map((r) => `+ ${r}`);
  if (!gone.length && !came.length) return ["(only the order of entries, or repeated entries, changed)"];
  const cut = (r) => (r.length > 240 ? `${r.slice(0, 239)}…` : r);
  const half = Math.ceil(max / 2);
  const keepGone = Math.min(gone.length, Math.max(half, max - came.length));
  const keepCame = Math.min(came.length, max - keepGone);
  const hidden = gone.length - keepGone + came.length - keepCame;
  // A long row is cut, unless that would make a removed row and an added one read the same.
  const kept = [...gone.slice(0, keepGone), ...came.slice(0, keepCame)];
  const cuts = kept.map((r) => cut(r).slice(2));
  const shown = kept.map((r, i) => (cuts.filter((c) => c === cuts[i]).length > 1 ? r : cut(r)));
  return shown.concat(hidden ? [`… ${hidden} more`] : []);
}
