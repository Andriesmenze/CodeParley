// The JSON Schema sent to Codex with `--output-schema` (plan §13.1, X3, D-08).
//
// Codex forwards it unchanged as a STRICT json_schema response format and validates
// nothing itself. Strict mode needs: `additionalProperties: false` on every object, every
// property listed in `required`, and nullable written as `type: [T, "null"]`. The zod
// schema in schemas/review.ts is the source of truth; this module generates the JSON
// Schema from it and normalizes zod's output into exactly that subset:
//  - `anyOf: [{type: T}, {type: "null"}]` becomes `type: [T, "null"]`;
//  - validation-only keywords (maxLength, maxItems, minimum, …) are dropped: the local zod
//    validation enforces them, and the strict subset the Gate A live review validated
//    (spike/lib/output-schema.mjs) had none;
//  - `integer` is written as `number` (as validated live); integrality is checked locally.
// `strictSubsetCheck` proves the result meets the subset (unit test and doctor).

import { z } from "zod";
import { sha256OfCanonicalJson } from "../../common/hash.js";
import { ReviewOutputSchema } from "../../schemas/review.js";

type Json = Record<string, unknown>;

const KEEP = new Set(["type", "properties", "required", "additionalProperties", "items", "enum", "description"]);

function normalize(node: unknown): Json {
  if (!node || typeof node !== "object") throw new Error("schema node is not an object");
  const n = node as Json;
  if (Array.isArray(n["anyOf"])) {
    const alts = n["anyOf"] as Json[];
    const nonNull = alts.filter((a) => a["type"] !== "null");
    if (alts.length === 2 && nonNull.length === 1) {
      const inner = normalize(nonNull[0]);
      const t = inner["type"];
      if (typeof t !== "string") throw new Error("nullable of a non-primitive is not supported in the strict subset");
      return { ...inner, type: [t, "null"] };
    }
    throw new Error("anyOf other than a nullable is not supported in the strict subset");
  }
  const out: Json = {};
  for (const [k, v] of Object.entries(n)) {
    if (!KEEP.has(k)) continue;
    if (k === "properties") {
      const props: Json = {};
      for (const [pk, pv] of Object.entries(v as Json)) props[pk] = normalize(pv);
      out[k] = props;
    } else if (k === "items") {
      out[k] = normalize(v);
    } else if (k === "type") {
      out[k] = v === "integer" ? "number" : v;
    } else {
      out[k] = v;
    }
  }
  return out;
}

/** The strict JSON Schema for ReviewOutput. */
export function reviewOutputJsonSchema(): Json {
  const raw = z.toJSONSchema(ReviewOutputSchema, { target: "draft-7" }) as Json;
  return normalize(raw);
}

/** Digest of the schema actually sent (recorded per review). */
export function reviewOutputSchemaDigest(): string {
  return sha256OfCanonicalJson(reviewOutputJsonSchema());
}

/** Prove a schema satisfies the strict subset. Returns the violations (empty = ok). */
export function strictSubsetCheck(schema: Json, path = "$"): string[] {
  const violations: string[] = [];
  const visit = (s: Json, p: string): void => {
    if ("anyOf" in s || "oneOf" in s || "allOf" in s || "$ref" in s) violations.push(`${p}: composition/ref keywords are not allowed`);
    const types = Array.isArray(s["type"]) ? (s["type"] as unknown[]) : [s["type"]];
    if (types.some((t) => typeof t !== "string")) violations.push(`${p}: missing or invalid type`);
    if (Array.isArray(s["type"]) && !(s["type"].length === 2 && s["type"].includes("null"))) violations.push(`${p}: a type array must be [T, "null"]`);
    if (types.includes("object")) {
      if (s["additionalProperties"] !== false) violations.push(`${p}: additionalProperties must be false`);
      const props = Object.keys((s["properties"] as Json | undefined) ?? {});
      const req = (s["required"] as string[] | undefined) ?? [];
      for (const k of props) if (!req.includes(k)) violations.push(`${p}.${k}: property not in required[]`);
      for (const k of req) if (!props.includes(k)) violations.push(`${p}: required lists unknown property ${k}`);
      for (const [k, sub] of Object.entries((s["properties"] as Json | undefined) ?? {})) visit(sub as Json, `${p}.${k}`);
    }
    if (types.includes("array")) {
      if (!s["items"]) violations.push(`${p}: array without items`);
      else visit(s["items"] as Json, `${p}[]`);
    }
  };
  visit(schema, path);
  return violations;
}
