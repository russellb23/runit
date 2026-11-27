#!/usr/bin/env node
/**
 * UI interactivity audit. Enforces the README rule "every UI element must do something".
 *
 *   npm run audit:ui            (from frontend/)
 *
 * Failures (exit code 1): a <button> with no handler, an empty onClick, an <a> without href or handler,
 * a <form> without onSubmit, a controlled input without onChange, or a card (accessrow, count-tile, ...)
 * that contains nothing interactive.
 * Warnings (review, do not fail): elements styled like controls (tag, badge, tile, pill) with no handler,
 * and disabled buttons that give no reason. Add `data-audit-ok` to an element to exempt it deliberately.
 */
const ts = require("typescript");
const fs = require("fs");
const file = process.argv[2] || "app/page.tsx";
const src = fs.readFileSync(file, "utf8");
const sf = ts.createSourceFile(
  file,
  src,
  ts.ScriptTarget.ES2020,
  true,
  ts.ScriptKind.TSX,
);
const line = (n) => sf.getLineAndCharacterOfPosition(n.getStart()).line + 1;
const snip = (n) =>
  src.slice(n.getStart(), n.getStart() + 100).replace(/\s+/g, " ");

// Whole class names only: "status" matches, "status-stats" (a layout wrapper) does not.
const LOOKS_LIKE_CONTROL =
  /(?<![\w-])(btn|tile|tag|chip|pill|badge|stat|tab|navitem|count-tile|status|conn|live-mark)(?![\w-])/;
const CARD =
  /\b(accessrow|count-tile|chart-card|connector-card|attention|team-leads|leaderboard-card|tenant-key-row)\b/;
const NATIVE = new Set(["button", "input", "select", "textarea", "a", "form"]);
const BUSY = /^\{(busy|authBusy|refreshing|saving|loading)(\|\|.*)?\}$/;
const fail = [],
  warn = [];

const attrsOf = (el) => {
  const m = {};
  (el.attributes?.properties || []).forEach((p) => {
    if (p.name)
      m[p.name.getText()] = p.initializer ? p.initializer.getText() : "true";
  });
  return m;
};
const handlerKeys = (a) => Object.keys(a).filter((k) => /^on[A-Z]/.test(k));
const hasInteractiveChild = (node) => {
  let found = false;
  (function walk(x) {
    if (found) return;
    if (ts.isJsxOpeningElement(x) || ts.isJsxSelfClosingElement(x)) {
      if (NATIVE.has(x.tagName.getText()) || handlerKeys(attrsOf(x)).length) {
        found = true;
        return;
      }
    }
    ts.forEachChild(x, walk);
  })(node);
  return found;
};
const enclosingForm = (n) => {
  for (let p = n.parent; p; p = p.parent)
    if (ts.isJsxElement(p) && p.openingElement.tagName.getText() === "form")
      return p;
  return null;
};

(function visit(n) {
  if (ts.isJsxElement(n) || ts.isJsxSelfClosingElement(n)) {
    const el = ts.isJsxElement(n) ? n.openingElement : n;
    const tag = el.tagName.getText(),
      a = attrsOf(el);
    const cls = (a.className || "").replace(/[{}`"$]/g, " ");
    if (!("data-audit-ok" in a)) {
      if (tag === "button") {
        const submits = !a.type || /submit/.test(a.type);
        const form = enclosingForm(n);
        if (
          !a.onClick &&
          !a.onMouseDown &&
          !(submits && form && attrsOf(form.openingElement).onSubmit)
        )
          fail.push([line(n), "button does nothing", snip(el)]);
        if (/^\{\s*\(\)\s*=>\s*\{\s*\}\s*\}$/.test(a.onClick || ""))
          fail.push([line(n), "empty onClick", snip(el)]);
        if (
          a.disabled &&
          !a.title &&
          !a["aria-label"] &&
          !BUSY.test(a.disabled)
        )
          warn.push([line(n), "disabled without a reason", a.disabled]);
      }
      if (tag === "a" && !a.href && !a.onClick)
        fail.push([line(n), "link without href or handler", snip(el)]);
      if (tag === "form" && !a.onSubmit)
        fail.push([line(n), "form without onSubmit", snip(el)]);
      if (
        ["input", "select", "textarea"].includes(tag) &&
        a.value &&
        !a.onChange &&
        !a.readOnly
      )
        fail.push([line(n), "controlled input without onChange", snip(el)]);
      if (
        ts.isJsxElement(n) &&
        CARD.test(cls) &&
        !handlerKeys(a).length &&
        !hasInteractiveChild(n)
      )
        fail.push([line(n), "card with nothing interactive in it", snip(el)]);
      if (
        !NATIVE.has(tag) &&
        !["label", "option"].includes(tag) &&
        LOOKS_LIKE_CONTROL.test(cls) &&
        !handlerKeys(a).length
      )
        warn.push([
          line(n),
          "styled like a control but static",
          `${tag} ${cls.trim().slice(0, 50)}`,
        ]);
    }
  }
  ts.forEachChild(n, visit);
})(sf);

const show = (title, rows) => {
  console.log(`\n${title}: ${rows.length}`);
  rows.forEach(([l, why, t]) => console.log(`  ${file}:${l}  ${why}  ${t}`));
};
show("FAILURES", fail);
show("WARNINGS (review)", warn);
process.exit(fail.length ? 1 : 0);
