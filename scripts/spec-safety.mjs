// Two checks on a spec's content, both recorded in index.json and flagged (⚠) in the nightly PR:
//
// surface   A fingerprint of where calls go and how they authenticate: servers, hosts, security schemes and
//           requirements. A vendor rarely changes these; when they do change, a person should look before
//           the new file is trusted, so the nightly PR is not merged automatically.
// suspicious Text in descriptions or summaries that reads like instructions to an AI agent ("ignore previous
//           instructions", chat-template tokens, hidden Unicode). Tools built from a spec pass this text to
//           a model, so a spec carrying it is held for review.

import { createHash } from "node:crypto";

// Phrases aimed at a model rather than a developer. Kept narrow: API docs say "you must", "call this
// endpoint" and "the token" all the time, so plain imperatives are not flagged.
export const INSTRUCTION_LIKE = [
  /\b(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|preceding|system)\s+(instructions?|prompts?|messages?|rules|context)/i,
  /\b(system|developer)\s+prompt\b/i,
  /\byou\s+are\s+(now\s+)?(an?\s+)?(ai|assistant|chatbot|language\s+model|llm|claude|chatgpt|gpt)\b/i,
  /<\|?\s*(im_start|im_end|endoftext|system|assistant|user)\s*\|?>/i,
  /\[\/?INST\]|<<\/?SYS>>/,
  /\bdo\s+not\s+(tell|inform|reveal\s+to|mention\s+to)\s+the\s+user\b/i,
  /\b(send|post|forward|exfiltrate|upload)\b[^.]{0,60}\b(api[\s_-]?keys?|access\s+tokens?|credentials|passwords?|secrets?)\b[^.]{0,40}\bto\s+(https?:\/\/|\S+@\S+)/i,
  /\b(ai|llm|agent|assistant|model)s?\b[^.]{0,30}\b(must|should)\s+(always\s+|now\s+|first\s+)?(ignore|call|invoke|execute|run|send)\b/i,
];
// Zero-width and bidirectional-override characters: invisible to a reviewer, readable by a model.
export const HIDDEN_CHARS = /[​-‏‪-‮⁠-⁤⁦-⁩﻿]/;

const TEXT_KEYS = new Set(["description", "summary", "title", "x-summary"]);

/** Up to `max` short samples of instruction-like or hidden text in a parsed spec. */
export function suspiciousText(doc, max = 3) {
  const found = [];
  const seen = new Set();
  const walk = (v, key, depth) => {
    if (found.length >= max || depth > 40 || v == null) return;
    if (typeof v === "string") {
      if (!TEXT_KEYS.has(key)) return;
      const hidden = HIDDEN_CHARS.test(v.replace(/^﻿/, ""));
      const hit = hidden ? null : INSTRUCTION_LIKE.find((re) => re.test(v));
      if (!hidden && !hit) return;
      const at = hit ? v.search(hit) : v.search(HIDDEN_CHARS);
      const sample = (hidden ? "hidden characters: " : "") + v.slice(Math.max(0, at - 20), at + 60).replace(/\s+/g, " ").replace(HIDDEN_CHARS, "␣");
      if (!seen.has(sample)) {
        seen.add(sample);
        found.push(sample);
      }
      return;
    }
    if (Array.isArray(v)) for (const x of v) walk(x, key, depth + 1);
    else if (typeof v === "object") for (const [k, x] of Object.entries(v)) walk(x, k, depth + 1);
  };
  walk(doc, "", 0);
  return found;
}

const canonical = (v) =>
  Array.isArray(v) ? `[${v.map(canonical).join(",")}]`
  : v && typeof v === "object" ? `{${Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(",")}}`
  : JSON.stringify(v);

const METHODS = ["get", "put", "post", "delete", "options", "head", "patch", "trace", "query"];

/** A short hash of where a spec's calls go and how they authenticate, or null for formats without one. */
export function surfaceOf(format, doc) {
  let surface = null;
  if (format.startsWith("openapi-")) {
    const perPath = [];
    for (const [p, item] of Object.entries(doc.paths ?? {})) {
      if (!item || typeof item !== "object") continue;
      if (item.servers) perPath.push([p, "*", item.servers]);
      for (const m of METHODS) {
        const op = item[m];
        if (op?.servers) perPath.push([p, m, op.servers]);
        if (op?.security) perPath.push([p, m, "security", op.security]);
      }
    }
    surface = { servers: doc.servers ?? null, schemes: doc.components?.securitySchemes ?? null, security: doc.security ?? null, perPath };
  } else if (format === "swagger-2.0") {
    const perOp = [];
    for (const [p, item] of Object.entries(doc.paths ?? {})) for (const m of METHODS) if (item?.[m]?.security) perOp.push([p, m, item[m].security]);
    surface = { host: doc.host ?? null, basePath: doc.basePath ?? null, schemes: doc.schemes ?? null, definitions: doc.securityDefinitions ?? null, security: doc.security ?? null, perOp };
  } else if (format === "google-discovery") {
    surface = { rootUrl: doc.rootUrl ?? null, servicePath: doc.servicePath ?? null, auth: doc.auth ?? null };
  } else if (format.startsWith("postman-")) {
    const hosts = new Set();
    const walk = (items) =>
      items?.forEach((it) => {
        const u = it.request?.url;
        const raw = typeof u === "string" ? u : u?.raw ?? (Array.isArray(u?.host) ? u.host.join(".") : u?.host);
        if (raw) hosts.add(String(raw).replace(/^\w+:\/\//, "").split(/[/?#]/)[0]);
        walk(it.item);
      });
    walk(doc.item);
    surface = { auth: doc.auth ?? null, hosts: [...hosts].sort() };
  }
  return surface && createHash("sha256").update(canonical(surface)).digest("hex").slice(0, 16);
}
