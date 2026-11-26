// Reproducible cold-load benchmark for web/dist (no chat server needed).
//
//   node web/perf.mjs --label baseline --runs 5
//   node web/perf.mjs --label after --runs 5
//   node web/perf.mjs --map web/perf-baseline.json web/perf-after.json
//
// Each run uses a fresh browser context with the service worker blocked, so the
// page always downloads the build. CPU throttling (--cpu 4) reproduces the
// mobile profile already used in web/README.md. Results are raw numbers: the
// --map mode computes the percentage change per metric.
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import zlib from "node:zlib";
import { fileURLToPath } from "node:url";
import { chromium } from "./node_modules/playwright/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DIST = path.join(HERE, "dist");
const args = process.argv.slice(2);
const flag = (name, fallback) => {
  const i = args.indexOf("--" + name);
  return i < 0 ? fallback : (args[i + 1] ?? fallback);
};
const LABEL = flag("label", "run");
const RUNS = Number(flag("runs", "5"));
const CPU = Number(flag("cpu", "1"));
const OUT = flag("out", path.join(HERE, `perf-${LABEL}.json`));

const MIME = {
  ".html": "text/html; charset=utf-8", ".mjs": "text/javascript; charset=utf-8",
  ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
  ".wasm": "application/wasm", ".json": "application/json", ".zip": "application/zip",
  ".gz": "application/gzip", ".pyc": "application/octet-stream", ".whl": "application/zip",
};

function serve() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const rel = decodeURIComponent(new URL(req.url, "http://x").pathname).replace(/^\/+/, "") || "index.html";
      const file = path.resolve(DIST, rel);
      if (!file.startsWith(path.resolve(DIST) + path.sep)) { res.writeHead(403).end(); return; }
      fs.readFile(file, (err, buf) => {
        if (err) { res.writeHead(404).end(); return; }
        const ext = path.extname(file);
        const gzip = ext !== ".gz" && /\bgzip\b/.test(req.headers["accept-encoding"] || "");
        const body = gzip ? zlib.gzipSync(buf) : buf;
        res.writeHead(200, {
          "Content-Type": MIME[ext] || "application/octet-stream",
          "Content-Length": body.length,
          ...(gzip ? { "Content-Encoding": "gzip" } : {}),
          "Cache-Control": "no-store",
        });
        res.end(body);
      });
    });
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

const metric = (entries, name) => entries.find((m) => m.name === name)?.value ?? null;

async function sample(browser, url, port) {
  const context = await browser.newContext({ serviceWorkers: "block" });
  const cdp = await context.newCDPSession(await context.newPage());
  const page = cdp._page ?? (await context.pages())[0];
  await cdp.send("Performance.enable");
  if (CPU !== 1) await cdp.send("Emulation.setCPUThrottlingRate", { rate: CPU });
  const before = metric((await cdp.send("Performance.getMetrics")).metrics, "ScriptDuration") ?? 0;
  const started = Date.now();
  await page.goto(url, { waitUntil: "domcontentloaded" });
  await page.waitForFunction(() => !document.getElementById("go")?.disabled, null, { timeout: 120000 });
  const wall = Date.now() - started;
  const after = (await cdp.send("Performance.getMetrics")).metrics;
  const data = await page.evaluate(() => {
    const pick = (type) => performance.getEntriesByType(type).map((e) => ({
      name: e.name.replace(location.origin, ""), start: Math.round(e.startTime), duration: Math.round(e.duration),
      encoded: e.encodedBodySize || 0, decoded: e.decodedBodySize || 0,
    }));
    return {
      marks: { ...window.crptoMetrics },
      paint: pick("paint"),
      nav: performance.getEntriesByType("navigation")[0] ? {
        dcl: Math.round(performance.getEntriesByType("navigation")[0].domContentLoadedEventEnd),
        load: Math.round(performance.getEntriesByType("navigation")[0].loadEventEnd),
      } : null,
      resources: pick("resource"),
      status: document.getElementById("status")?.textContent,
    };
  });
  await context.close();
  const js = data.resources.filter((r) => /\.(mjs|js)(\?|$)/.test(r.name) && r.decoded);
  const css = data.resources.filter((r) => /\.css(\?|$)/.test(r.name) && r.decoded);
  const beforeReady = data.resources.filter((r) => r.start <= (data.marks.ready ?? wall));
  return {
    wall,
    marks: data.marks,
    nav: data.nav,
    fcp: data.paint.find((p) => p.name === "first-contentful-paint")?.start ?? null,
    scriptSeconds: Number(((metric(after, "ScriptDuration") ?? 0) - before).toFixed(3)),
    taskSeconds: Number((metric(after, "TaskDuration") ?? 0).toFixed(3)),
    heapMB: Number(((metric(after, "JSHeapUsedSize") ?? 0) / 1e6).toFixed(1)),
    js: {
      files: js.length,
      decodedKB: Math.round(js.reduce((s, r) => s + r.decoded, 0) / 1024),
      encodedKB: Math.round(js.reduce((s, r) => s + r.encoded, 0) / 1024),
      names: js.map((r) => `${r.name} (${Math.round(r.decoded / 1024)} KB)`),
    },
    css: { decodedKB: Math.round(css.reduce((s, r) => s + r.decoded, 0) / 1024) },
    beforeReady: {
      files: beforeReady.length,
      encodedKB: Math.round(beforeReady.reduce((s, r) => s + r.encoded, 0) / 1024),
      decodedKB: Math.round(beforeReady.reduce((s, r) => s + r.decoded, 0) / 1024),
    },
    status: data.status,
    port,
  };
}

function summarize(samples) {
  const med = (key) => {
    const vals = samples.map((s) => key(s)).filter((v) => typeof v === "number" && Number.isFinite(v)).sort((a, b) => a - b);
    return vals.length ? Math.round(vals[Math.floor(vals.length / 2)] * 100) / 100 : null;
  };
  return {
    ready: med((s) => s.marks.ready), pyodide: med((s) => s.marks.pyodide), packages: med((s) => s.marks.packages),
    extras: med((s) => s.marks.extras), wall: med((s) => s.wall), fcp: med((s) => s.fcp),
    scriptSeconds: med((s) => s.scriptSeconds), taskSeconds: med((s) => s.taskSeconds), heapMB: med((s) => s.heapMB),
    jsKB: med((s) => s.js.decodedKB), cssKB: med((s) => s.css.decodedKB),
    firstLoadKB: med((s) => s.beforeReady.encodedKB), jsFiles: med((s) => s.js.files),
    // derived phases: pyodide boot, wheel load, and everything after it (unzip,
    // IDBFS, and the app/Textual imports that the login page used to pay for)
    unzipAndImportsMs: med((s) => (s.marks.ready ?? 0) - (s.marks.packages ?? 0)),
  };
}

function map(before, after) {
  const pct = (b, a) => (typeof b === "number" && typeof a === "number" && b ? Math.round(((b - a) / b) * 1000) / 10 : null);
  const b = before.summary, a = after.summary;
  const rows = Object.keys(b).map((k) => ({ metric: k, before: b[k], after: a[k], improvementPct: pct(b[k], a[k]) }));
  console.log(JSON.stringify({ baseline: { label: before.label, cpu: before.cpu, summary: b },
                               after: { label: after.label, cpu: after.cpu, summary: a }, rows }, null, 2));
}

if (args.includes("--resummarize")) {
  const file = args[args.indexOf("--resummarize") + 1];
  const result = JSON.parse(fs.readFileSync(file, "utf8"));
  result.summary = summarize(result.samples);
  fs.writeFileSync(file, JSON.stringify(result, null, 2) + "\n");
  console.log(JSON.stringify(result.summary, null, 2));
} else if (args.includes("--map")) {
  map(JSON.parse(fs.readFileSync(args[args.indexOf("--map") + 1], "utf8")),
      JSON.parse(fs.readFileSync(args[args.indexOf("--map") + 2], "utf8")));
} else {
  const server = await serve();
  const port = server.address().port;
  const browser = await chromium.launch({ headless: true });
  const samples = [];
  try {
    for (let i = 0; i < RUNS; i++) {
      const s = await sample(browser, `http://127.0.0.1:${port}/`, port);
      samples.push(s);
      console.log(`run ${i + 1}/${RUNS}: ready=${s.marks.ready} ms, wall=${s.wall} ms, script=${s.scriptSeconds} s, js=${s.js.decodedKB} KB`);
    }
  } finally {
    await browser.close();
    server.close();
  }
  const result = { label: LABEL, cpu: CPU, runs: RUNS, timestamp: new Date().toISOString(),
                   baselineCommit: process.env.PERF_COMMIT || null, samples, summary: summarize(samples) };
  fs.writeFileSync(OUT, JSON.stringify(result, null, 2) + "\n");
  console.log(`\n${LABEL}: wrote ${OUT}`);
  console.log(JSON.stringify(result.summary, null, 2));
}
