// Same precompile as precompile.mjs, but runs Pyodide inside Chromium. Used by
// build.py when WEB_PRECOMPILE_BROWSER=1: on Windows the cryptography wheel
// aborts under Node, while in the browser (the real target) it loads fine.
//
//   node web/precompile-browser.mjs VENDOR_DIR APP_ZIP OUT_DIR
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "./node_modules/playwright/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const [vendorArg, appZipArg, outArg] = process.argv.slice(2);
const VENDOR = path.resolve(vendorArg);
const APP_ZIP = path.resolve(appZipArg);
const OUT = path.resolve(outArg);
const MIME = { ".mjs": "text/javascript", ".js": "text/javascript", ".wasm": "application/wasm",
               ".json": "application/json", ".whl": "application/zip", ".zip": "application/zip" };

const page = `<!doctype html><meta charset="utf-8"><body><script type="module">
import { loadPyodide } from "./vendor/pyodide/pyodide.mjs";
import { COMPILE_PY } from "./precompile-core.mjs";
const b64 = (u8) => { let s = ""; for (let i = 0; i < u8.length; i += 32768) s += String.fromCharCode(...u8.subarray(i, i + 32768)); return btoa(s); };
try {
  const py = await loadPyodide({ indexURL: "./vendor/pyodide/", fullStdLib: false, stdout: () => {}, stderr: (l) => console.error(l) });
  const manifest = await (await fetch("./manifest.json")).json();
  const lock = await (await fetch("./vendor/pyodide/pyodide-lock.json")).json();
  await py.loadPackage(manifest.pyodide_packages.map((n) => "./vendor/pyodide/" + lock.packages[n].file_name), { messageCallback: () => {} });
  await py.loadPackage(manifest.wheels.map((f) => "./vendor/wheels/" + f), { messageCallback: () => {} });
  py.unpackArchive(new Uint8Array(await (await fetch("./app.zip")).arrayBuffer()), "zip", { extractDir: "/app" });
  py.runPython(\`
import os, sys
sys.path.insert(0, "/app")
os.environ["CRPTOCHAT_HOME"] = "/tmp/precompile-home"
import crptoweb.boot, crptochat.tui, crptoweb.keys
crptoweb.boot.prepare()
\`);
  py.globals.set("COMPILED_PACKAGES", py.toPy(manifest.pyodide_packages));
  const result = py.runPython(COMPILE_PY);
  const [stdlibZip, siteZip, laterZip, stdlibRest, nStd, nCore, nSite, tops] = result.toJs();
  window.__done = { stdlibZip: b64(stdlibZip), siteZip: b64(siteZip), laterZip: b64(laterZip),
                    stdlibRest: b64(stdlibRest), nStd, nCore, nSite, tops };
} catch (err) { window.__done = { error: String(err && err.message || err) }; }
</script></body>`;

const server = http.createServer((req, res) => {
  const name = new URL(req.url, "http://x").pathname;
  let file = null;
  if (name === "/" || name === "/index.html") { res.writeHead(200, { "Content-Type": "text/html" }); res.end(page); return; }
  if (name === "/app.zip") file = APP_ZIP;
  else if (name === "/precompile-core.mjs") file = path.join(HERE, "precompile-core.mjs");
  else if (name === "/manifest.json") file = path.join(VENDOR, "manifest.json");
  else if (name.startsWith("/vendor/")) file = path.join(VENDOR, name.slice(8));
  else { res.writeHead(404).end(); return; }
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404).end(); return; }
    res.writeHead(200, { "Content-Type": MIME[path.extname(file)] || "application/octet-stream", "Content-Length": buf.length });
    res.end(buf);
  });
});

await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
const url = `http://127.0.0.1:${server.address().port}/`;
const browser = await chromium.launch({ headless: true });
try {
  const p = await browser.newPage();
  p.on("console", (m) => { if (m.type() === "error") console.error(m.text()); });
  p.on("pageerror", (e) => console.error(String(e)));
  await p.goto(url, { waitUntil: "domcontentloaded" });
  await p.waitForFunction(() => !!window.__done, null, { timeout: 180000 });
  const out = await p.evaluate(() => window.__done);
  if (out.error) throw new Error(out.error);
  fs.mkdirSync(OUT, { recursive: true });
  for (const [key, name] of [["stdlibZip", "python_stdlib.zip"], ["siteZip", "site.zip.gz"],
                             ["laterZip", "later.zip.gz"], ["stdlibRest", "stdlib-rest.zip.gz"]]) {
    fs.writeFileSync(path.join(OUT, name), Buffer.from(out[key], "base64"));
  }
  console.log(`pré-compilado no navegador: ${out.nStd} módulos da stdlib (${out.nCore} no boot), ${out.nSite} de pacotes e app (compilados só .pyc: ${out.tops.join(", ")})`);
} finally {
  await browser.close();
  server.close();
}
