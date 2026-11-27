#!/usr/bin/env node
/**
 * Verifies the inbound connector catalog (src/connectors/catalog.json) is internally consistent and that
 * every connector's sample payload maps onto a relay using the connector's own field definitions.
 *
 *   npm run test:connectors      (from frontend/)
 */
const fs = require("fs");
const path = require("path");
const ts = require("typescript");

const root = path.resolve(__dirname, "..");
const source = fs.readFileSync(
  path.join(root, "app", "connectorMapping.ts"),
  "utf8",
);
const compiled = ts.transpileModule(source, {
  compilerOptions: {
    module: ts.ModuleKind.CommonJS,
    target: ts.ScriptTarget.ES2020,
  },
}).outputText;
const mod = { exports: {} };
new Function("exports", "module", compiled)(mod.exports, mod);
const { resolvePath, previewMapping, MAPS_TO_TARGETS, SEVERITIES } =
  mod.exports;

const catalog = JSON.parse(
  fs.readFileSync(
    path.resolve(root, "..", "src", "connectors", "catalog.json"),
    "utf8",
  ),
).connectors;
let failures = 0,
  checks = 0;
const check = (ok, message) => {
  checks++;
  if (!ok) {
    failures++;
    console.log("  FAIL", message);
  }
};
const PATH_RE = /^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$/;

// ---- engine behaviour
const sns = {
  Message: JSON.stringify({
    AlarmName: "HighCPU",
    Trigger: { Namespace: "AWS/EC2" },
  }),
};
check(resolvePath({ a: [{ b: "x" }] }, "a.0.b") === "x", "array index path");
check(
  resolvePath({ a: [] }, "a.0.b") === undefined,
  "missing array element is undefined",
);
check(
  resolvePath({ a: { b: 1 } }, "a.c") === undefined,
  "missing key is undefined",
);
check(
  resolvePath(sns, "Message.AlarmName") === "HighCPU",
  "JSON string is decoded while traversing",
);
check(
  resolvePath(sns, "Message.Trigger.Namespace") === "AWS/EC2",
  "decoded JSON can be traversed deeper",
);
check(
  typeof resolvePath(sns, "Message") === "string",
  "the final value is not decoded",
);
check(
  resolvePath({ a: "not json" }, "a.b") === undefined,
  "non-JSON string stops traversal",
);
const fields = [
  { path: "t", type: "string", required: true, maps_to: "title" },
  { path: "k", type: "string", required: true, maps_to: "dedup_key" },
  { path: "s", type: "string", required: false, maps_to: "severity" },
];
let p = previewMapping(
  fields,
  [{ from: "P1", to: "critical" }],
  { t: "T", k: "K", s: "p1" },
  { default_severity: "info", source: "x" },
  "c",
);
check(
  p.relay.severity === "critical" && p.missing.length === 0,
  "severity map is case-insensitive",
);
p = previewMapping(
  fields,
  [],
  { t: "T", k: "K", s: "weird" },
  { default_severity: "error" },
  "c",
);
check(
  p.relay.severity === "error" && p.notes.length === 1,
  "unknown severity falls back to the default with a note",
);
p = previewMapping(fields, [], { k: "K" }, {}, "c");
check(
  p.missing.length === 1 && p.missing[0].maps_to === "title",
  "missing required field is reported",
);
p = previewMapping(fields, [], { t: "T", k: 7 }, {}, "c");
check(p.relay.dedup_key === "7", "numbers are converted to text");
p = previewMapping(fields, [], { t: { nested: 1 }, k: "K" }, {}, "c");
check(
  p.missing.some((m) => m.maps_to === "title"),
  "an object is not usable as text",
);

// ---- catalog structure
console.log(`catalog: ${catalog.length} connectors`);
check(catalog.length >= 15, "at least 15 inbound connectors");
const keys = catalog.map((c) => c.key);
check(new Set(keys).size === keys.length, "connector keys are unique");
const LEGACY = [
  "smtp_email",
  "signed_webhook",
  "slack",
  "microsoft_teams",
  "jira",
  "servicenow",
];
check(
  LEGACY.every((k) => !keys.includes(k)),
  "outbound connectors are not in the catalog",
);

for (const c of catalog) {
  const at = `[${c.key}]`;
  check(c.direction === "inbound", `${at} is inbound`);
  check(
    ["Monitoring", "Cloud", "Uptime", "CI/CD"].includes(c.category),
    `${at} has a known category (${c.category})`,
  );
  check(c.name && c.summary && c.format, `${at} has name, summary, and format`);
  check(
    typeof c.sample_payload === "object" && c.sample_payload !== null,
    `${at} has a sample payload`,
  );
  const cfg = Object.fromEntries(c.config_fields.map((f) => [f.key, f]));
  check(
    cfg.source && cfg.source.required && cfg.source.default,
    `${at} has a required source with a default`,
  );
  check(
    cfg.default_severity &&
      cfg.default_severity.required &&
      cfg.default_severity.default === "warning" &&
      cfg.default_severity.kind === "select",
    `${at} has a required default severity`,
  );
  check(
    new Set(c.config_fields.map((f) => f.key)).size === c.config_fields.length,
    `${at} config field keys are unique`,
  );
  for (const f of c.config_fields) {
    check(
      f.kind === "text" ||
        (f.kind === "select" && f.options && f.options.length),
      `${at}.${f.key} kind is valid`,
    );
    if (f.kind === "select" && f.default)
      check(
        f.options.includes(f.default),
        `${at}.${f.key} default is one of its options`,
      );
    check(
      !/password|token|secret|api_?key|access_?key/i.test(f.key),
      `${at}.${f.key} is not a credential field name`,
    );
  }
  const seen = new Set();
  for (const f of c.payload_fields) {
    check(
      PATH_RE.test(f.path) && f.path.length <= 200,
      `${at} path is valid: ${f.path}`,
    );
    check(
      ["string", "number", "boolean", "object", "array"].includes(f.type),
      `${at} ${f.path} has a valid type`,
    );
    check(
      MAPS_TO_TARGETS.includes(f.maps_to),
      `${at} ${f.path} maps to a known target (${f.maps_to})`,
    );
    check(
      !f.mandatory || f.required === true,
      `${at} ${f.path} mandatory implies required`,
    );
    check(
      !f.description || f.description.length <= 300,
      `${at} ${f.path} description is short enough`,
    );
    const id = `${f.path}→${f.maps_to}`;
    check(!seen.has(id), `${at} ${id} is not duplicated`);
    seen.add(id);
  }
  const targets = c.payload_fields.map((f) => f.maps_to);
  check(
    new Set(targets).size === targets.length,
    `${at} each relay field has one source path`,
  );
  for (const must of ["dedup_key", "title"])
    check(
      c.payload_fields.some((f) => f.maps_to === must && f.mandatory),
      `${at} ${must} is mandatory`,
    );
  check(c.payload_fields.length <= 50, `${at} has at most 50 payload fields`);
  for (const m of c.severity_map)
    check(
      SEVERITIES.includes(m.to),
      `${at} severity map target ${m.to} is valid`,
    );
  const froms = c.severity_map.map((m) => m.from.toLowerCase());
  check(
    new Set(froms).size === froms.length,
    `${at} severity map has no duplicate sources`,
  );
  if (c.severity_map.length)
    check(
      c.payload_fields.some((f) => f.maps_to === "severity"),
      `${at} has a severity map and a severity field`,
    );

  // the sample payload must satisfy the connector's own definitions
  const preview = previewMapping(
    c.payload_fields,
    c.severity_map,
    c.sample_payload,
    Object.fromEntries(
      c.config_fields.filter((f) => f.default).map((f) => [f.key, f.default]),
    ),
    c.key,
  );
  check(
    preview.missing.length === 0,
    `${at} sample payload has every required field (missing: ${preview.missing.map((m) => m.path).join(", ")})`,
  );
  check(preview.relay.dedup_key.length > 0, `${at} sample yields a dedup key`);
  check(preview.relay.title.length > 0, `${at} sample yields a title`);
  check(
    SEVERITIES.includes(preview.relay.severity),
    `${at} sample yields a valid severity`,
  );
  const unmapped = c.payload_fields.filter(
    (f) =>
      !["severity"].includes(f.maps_to) &&
      f.path &&
      resolvePath(c.sample_payload, f.path) === undefined,
  );
  check(
    unmapped.length === 0,
    `${at} every defined path exists in the sample (absent: ${unmapped.map((f) => f.path).join(", ")})`,
  );
  if (c.severity_map.length) {
    const raw = resolvePath(
      c.sample_payload,
      c.payload_fields.find((f) => f.maps_to === "severity").path,
    );
    check(
      raw === undefined ||
        c.severity_map.some(
          (m) => m.from.toLowerCase() === String(raw).toLowerCase(),
        ),
      `${at} the sample's severity (${raw}) is covered by its severity map`,
    );
  }

  // sender templates must agree with the mandatory paths
  if (c.sender_template) {
    if (!c.sender_template.includes("{{")) {
      let body;
      try {
        body = JSON.parse(c.sender_template);
      } catch {
        body = null;
      }
      check(body !== null, `${at} sender template is valid JSON`);
      if (body)
        for (const f of c.payload_fields.filter((x) => x.mandatory))
          check(
            resolvePath(body, f.path) !== undefined,
            `${at} sender template includes mandatory path ${f.path}`,
          );
    } else {
      for (const f of c.payload_fields.filter((x) => x.mandatory))
        check(
          c.sender_template.includes(`"${f.path.split(".")[0]}"`),
          `${at} sender template includes ${f.path}`,
        );
    }
  }
}
console.log(`${checks} checks, ${failures} failure(s)`);
process.exit(failures ? 1 : 0);
