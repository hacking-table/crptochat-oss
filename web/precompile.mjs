// Precompiles the Python the browser runs, with Pyodide's own Python (same
// version and bytecode as in the page), so the page does not compile it again
// on every visit. Used by build.py; needs Node 18+ and `npm ci` in web/.
//
//   node web/precompile.mjs VENDOR_DIR APP_ZIP OUT_DIR
//
// Writes to OUT_DIR:
//   python_stdlib.zip   the part of the standard library the page imports before
//                       the login, as bytecode (.pyc in place of .py)
//   stdlib-rest.zip.gz     the rest of it, fetched while the person types
//   later.zip.gz           packages not needed to open the chat (Pygments, only for
//                       syntax colours), for zipimport once the chat is open
//   site.zip.gz            the pure-Python packages (Textual, Rich...) and the app,
//                       installed, as bytecode (.pyc in place of .py, plus their
//                       data files); and __pycache__ for the compiled packages
//                       (cryptography...) that loadPackage installs with sources
//
// Sourceless: smaller and faster to unpack; tracebacks show no source lines.
//
// Bytecode is "unchecked hash" (PEP 552): no timestamps, never revalidated
// against the source, the same bytes for the same source.
import { loadPyodide } from "./vendor/pyodide/pyodide.mjs";
import fs from "node:fs";
import path from "node:path";
import { COMPILE_PY, unwrap } from "./precompile-core.mjs";

const [vendor, appZip, outDir] = process.argv.slice(2).map((p) => path.resolve(p));
const manifest = JSON.parse(fs.readFileSync(path.join(vendor, "manifest.json"), "utf8"));
const toPath = (p) => p.replace(/\\/g, "/");
const py = await loadPyodide({ indexURL: toPath(path.join(vendor, "pyodide")) + "/", fullStdLib: false, stdout: () => {}, stderr: (l) => console.error(l) });
const lock = JSON.parse(fs.readFileSync(path.join(vendor, "pyodide", "pyodide-lock.json"), "utf8"));
await py.loadPackage(manifest.pyodide_packages.map((n) => toPath(path.join(vendor, "pyodide", lock.packages[n].file_name))), { messageCallback: () => {} });
await py.loadPackage(manifest.wheels.map((f) => toPath(path.join(vendor, "wheels", f))), { messageCallback: () => {} });
py.unpackArchive(new Uint8Array(fs.readFileSync(appZip)), "zip", { extractDir: "/app" });

// Import the union of boot + chat modules here so the stdlib each one needs
// stays in the zip Python starts with. The page itself imports only
// crptoweb.boot before the login and brings tui/Textual in at launch(); the
// classification is deliberately wider than the boot set.
py.runPython(`
import os, sys
sys.path.insert(0, "/app")
os.environ["CRPTOCHAT_HOME"] = "/tmp/precompile-home"
import crptoweb.boot, crptochat.tui, crptoweb.keys
crptoweb.boot.prepare()
`);
py.globals.set("COMPILED_PACKAGES", py.toPy(manifest.pyodide_packages));
const { stdlibZip, siteZip, laterZip, stdlibRest, nStd, nCore, nSite, tops } = unwrap(py.runPython(COMPILE_PY));
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, "python_stdlib.zip"), stdlibZip);
fs.writeFileSync(path.join(outDir, "site.zip.gz"), siteZip);
fs.writeFileSync(path.join(outDir, "later.zip.gz"), laterZip);
fs.writeFileSync(path.join(outDir, "stdlib-rest.zip.gz"), stdlibRest);
console.log(`pré-compilado: ${nStd} módulos da stdlib (${nCore} no boot), ${nSite} de pacotes e app (compilados só .pyc: ${tops.join(", ")})`);
