#!/usr/bin/env node
import fs from "node:fs/promises";
import path from "node:path";
import { chromium } from "playwright";

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const key = argv[i];
    if (!key.startsWith("--")) continue;
    const val = argv[i + 1];
    out[key.slice(2)] = val;
    i += 1;
  }
  return out;
}

function headerFromInput(raw) {
  const val = String(raw || "").trim();
  if (!val) return null;
  const idx = val.indexOf(":");
  if (idx <= 0) return null;
  const name = val.slice(0, idx).trim();
  const value = val.slice(idx + 1).trim();
  if (!name || !value) return null;
  return { name, value };
}

function sameOrigin(base, target) {
  try {
    const a = new URL(base);
    const b = new URL(target, base);
    return a.origin === b.origin;
  } catch {
    return false;
  }
}

async function writeJSONL(filePath, rows) {
  const content = rows.map((r) => JSON.stringify(r)).join("\n");
  await fs.writeFile(filePath, content ? `${content}\n` : "", "utf8");
}

async function writeSummaryCSV(filePath, data) {
  const lines = ["metric,value"];
  Object.entries(data).forEach(([k, v]) => lines.push(`${k},${v}`));
  await fs.writeFile(filePath, `${lines.join("\n")}\n`, "utf8");
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const target = String(args.target || "").trim();
  const outDir = String(args["out-dir"] || "").trim();
  const maxPages = Number.parseInt(args["max-pages"] || "30", 10);
  const maxClicks = Number.parseInt(args["max-clicks"] || "140", 10);
  if (!target || !outDir) {
    throw new Error("Usage: --target <url> --out-dir <path> [--auth-header 'Authorization: Bearer ...']");
  }
  const marker = `BFLOW_XSS_${Date.now()}`;
  const payload = `"><img src=x onerror="window.__bflowXSS='${marker}'">`;

  await fs.mkdir(outDir, { recursive: true });
  const reflectedHits = [];
  const domHits = [];
  const storedHits = [];
  const visited = new Set();
  const queue = [target];
  const discovered = new Set([target]);
  let clickActions = 0;
  let formActions = 0;
  let queryActions = 0;

  const browser = await chromium.launch({ headless: true });
  const contextOpts = {};
  const hdr = headerFromInput(args["auth-header"]);
  if (hdr) contextOpts.extraHTTPHeaders = { [hdr.name]: hdr.value };
  const context = await browser.newContext(contextOpts);
  const page = await context.newPage();

  page.on("dialog", async (dialog) => {
    domHits.push({
      type: "dialog",
      url: page.url(),
      message: dialog.message(),
      marker,
      at: new Date().toISOString(),
    });
    try { await dialog.dismiss(); } catch {}
  });

  async function collectLinks() {
    const hrefs = await page.$$eval("a[href]", (els) => els.map((e) => e.getAttribute("href")).filter(Boolean));
    hrefs.forEach((href) => {
      try {
        const abs = new URL(href, page.url()).toString();
        if (sameOrigin(target, abs) && !discovered.has(abs)) {
          discovered.add(abs);
          queue.push(abs);
        }
      } catch {}
    });
  }

  async function probeQuery(urlText) {
    try {
      const u = new URL(urlText);
      const keys = new Set([...u.searchParams.keys(), "q", "search", "s"]);
      for (const key of keys) {
        u.searchParams.set(key, payload);
        const probeURL = u.toString();
        queryActions += 1;
        await page.goto(probeURL, { waitUntil: "domcontentloaded", timeout: 20000 });
        const html = await page.content();
        if (html.includes(marker)) {
          reflectedHits.push({
            type: "query-reflection",
            url: probeURL,
            param: key,
            marker,
            at: new Date().toISOString(),
          });
        }
        const fired = await page.evaluate(() => window.__bflowXSS || null);
        if (fired === marker) {
          domHits.push({
            type: "query-dom-exec",
            url: probeURL,
            param: key,
            marker,
            at: new Date().toISOString(),
          });
        }
      }
    } catch {}
  }

  async function fuzzForms() {
    const forms = await page.$$("form");
    for (const form of forms) {
      const textInputs = await form.$$(
        "input[type='text'], input[type='search'], input[type='email'], input:not([type]), textarea"
      );
      if (!textInputs.length) continue;
      for (const input of textInputs) {
        try {
          await input.fill(payload);
        } catch {}
      }
      formActions += 1;
      try {
        await Promise.allSettled([
          page.waitForLoadState("domcontentloaded", { timeout: 12000 }),
          form.evaluate((f) => f.requestSubmit ? f.requestSubmit() : f.submit()),
        ]);
      } catch {}
      const html = await page.content();
      if (html.includes(marker)) {
        reflectedHits.push({
          type: "form-reflection",
          url: page.url(),
          marker,
          at: new Date().toISOString(),
        });
      }
      const fired = await page.evaluate(() => window.__bflowXSS || null);
      if (fired === marker) {
        domHits.push({
          type: "form-dom-exec",
          url: page.url(),
          marker,
          at: new Date().toISOString(),
        });
      }
    }
  }

  async function clickAround() {
    const clickables = await page.$$("button, a[href], input[type='submit'], [role='button']");
    for (const el of clickables) {
      if (clickActions >= maxClicks) break;
      clickActions += 1;
      try {
        await Promise.allSettled([
          page.waitForLoadState("domcontentloaded", { timeout: 7000 }),
          el.click({ timeout: 3000 }),
        ]);
      } catch {}
      const cur = page.url();
      if (sameOrigin(target, cur) && !discovered.has(cur)) {
        discovered.add(cur);
        queue.push(cur);
      }
    }
  }

  while (queue.length && visited.size < maxPages) {
    const next = queue.shift();
    if (!next || visited.has(next)) continue;
    if (!sameOrigin(target, next)) continue;
    visited.add(next);
    try {
      await page.goto(next, { waitUntil: "domcontentloaded", timeout: 25000 });
    } catch {
      continue;
    }
    await collectLinks();
    await probeQuery(next);
    await fuzzForms();
    await clickAround();
  }

  // Simple stored-XSS revisit pass.
  for (const u of [...visited].slice(0, maxPages)) {
    try {
      const parsed = new URL(u);
      if (parsed.search.includes(marker)) continue;
      await page.goto(u, { waitUntil: "domcontentloaded", timeout: 20000 });
      const html = await page.content();
      const fired = await page.evaluate(() => window.__bflowXSS || null);
      if (html.includes(marker) || fired === marker) {
        storedHits.push({
          type: fired === marker ? "stored-dom-exec" : "stored-reflection",
          url: u,
          marker,
          at: new Date().toISOString(),
        });
      }
    } catch {}
  }

  await writeJSONL(path.join(outDir, "reflected_hits.jsonl"), reflectedHits);
  await writeJSONL(path.join(outDir, "dom_hits.jsonl"), domHits);
  await writeJSONL(path.join(outDir, "stored_hits.jsonl"), storedHits);
  await fs.writeFile(path.join(outDir, "visited_urls.txt"), `${[...visited].join("\n")}\n`, "utf8");
  await writeSummaryCSV(path.join(outDir, "summary.csv"), {
    target,
    visited_pages: visited.size,
    discovered_urls: discovered.size,
    query_actions: queryActions,
    form_actions: formActions,
    click_actions: clickActions,
    reflected_hits: reflectedHits.length,
    dom_hits: domHits.length,
    stored_hits: storedHits.length,
  });

  await context.close();
  await browser.close();
}

main().catch((err) => {
  console.error(err?.stack || String(err));
  process.exitCode = 1;
});
