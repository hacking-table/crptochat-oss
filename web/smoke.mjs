// Smoke test of web/dist (CI): loads the build the way main.js does, under Node,
// and checks that the precompiled bytecode imports and works.
//
//   node web/smoke.mjs
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";

// everything of the build is under dist/b/<build id>/
const root = path.join(path.dirname(new URL(import.meta.url).pathname), "dist");
const builds = fs.readdirSync(path.join(root, "b"));
if (builds.length !== 1) throw new Error(`esperava um build em dist/b/, achei ${builds.length}`);
const dist = path.join(root, "b", builds[0]) + "/";
const page = fs.readFileSync(path.join(root, "index.html"), "utf8");
for (const ref of ["main.js", "style.css"]) {
  if (!page.includes(`b/${builds[0]}/${ref}`)) throw new Error(`index.html não aponta para b/${builds[0]}/${ref}`);
}
// xterm is loaded after the login, so it is no longer a link in index.html.
const client = fs.readFileSync(path.join(dist, "main.js"), "utf8");
for (const ref of ['import("./vendor/xterm/xterm.mjs")', 'vendor/xterm/xterm.css']) {
  if (!client.includes(ref)) throw new Error(`main.js não carrega ${ref} sob demanda`);
}
const { loadPyodide } = await import(dist + "vendor/pyodide/pyodide.mjs");
const gz = (name) => new Uint8Array(zlib.gunzipSync(fs.readFileSync(dist + "py/" + name)));
const py = await loadPyodide({ indexURL: dist + "vendor/pyodide/", stdLibURL: dist + "py/python_stdlib.zip",
                               stdout: () => {}, stderr: () => {} });
await py.loadPackage(["cryptography"], { messageCallback: () => {} });
py.unpackArchive(gz("site.zip.gz"), "zip", { extractDir: "/" });

const run = (label, code) => {
  try {
    console.log(`ok  ${label}: ${py.runPython(code)}`);
  } catch (err) {
    console.log(`FALHOU  ${label}: ${String(err.message).split("\n").slice(-4).join(" | ")}`);
    process.exitCode = 1;
  }
};

// 1. what the page imports before the login, with only the boot part of the stdlib
run("boot sem o resto da stdlib", `
import sys, importlib
sys.path.insert(0, "/app"); importlib.invalidate_caches()
import crptoweb.boot, crptoweb.keys
crptoweb.boot.prepare()
"crptoweb.boot, crptoweb.keys (sem Textual)"`);

// 1b. the rest of what runs in the page: the WebSocket transport, the Textual driver, the client
run("transporte, driver e cliente", `
import crptoweb.net, crptoweb.driver
from crptoweb.wire import check_url
from crptochat.client import ChatClient
assert crptoweb.net.WebSocketStream and issubclass(crptoweb.driver.XtermDriver, __import__("textual.driver").driver.Driver)
assert check_url("wss://chat.exemplo.org") == ("chat.exemplo.org", 443, True)
"crptoweb.net, crptoweb.driver, ChatClient"`);

// 2. a key made and opened in the browser's file system
run("chave", `
from crptoweb import keys
made = keys.create_key("smoke", "senha-do-smoke")
assert keys.check_passphrase("smoke", "senha-do-smoke") == made
keys.export_key("smoke")[:12]`);

// 3. the zips fetched while the person types: rest of the stdlib and Pygments
for (const name of ["stdlib-rest.zip", "later.zip"]) py.FS.writeFile("/lib/" + name, gz(name + ".gz"));
run("stdlib restante e pygments", `
import crptoweb.mount
for name in ("/lib/stdlib-rest.zip", "/lib/later.zip"):
    crptoweb.mount.mount(name)                    # as main.js does
import urllib.request, zipfile, wave
import crptochat.update, crptochat.audio, crptochat.relayfile
from rich.console import Console
from rich.syntax import Syntax
c = Console(record=True, width=40, color_system="truecolor")
c.print(Syntax("x = 1", "python"))
assert "\\x1b[" in c.export_text(styles=True)
"urllib, zipfile, wave, update/audio/relayfile, pygments"`);

// 3b. submodules of packages that came from the boot zip but live in the later
// one: codecs are looked up by name when first used ("idna" for any https host)
run("codecs depois do boot e modo navegador", `
import codecs, crptochat.tui
for name in ("idna", "cp1252", "latin-1", "utf-16", "cp437", "mac-roman"):
    codecs.lookup(name)
assert "crptochat.acpt.app.br".encode("idna") == b"crptochat.acpt.app.br"
assert crptochat.tui.IN_BROWSER                   # no update check: the site updates the page
"idna e outros codecs; IN_BROWSER"`);

// 4. no source shipped: bytecode only (tracebacks have no source lines)
run("só bytecode", `
import crptochat.tui, textual, os
assert crptochat.tui.__file__.endswith(".pyc") and textual.__file__.endswith(".pyc"), (crptochat.tui.__file__, textual.__file__)
"crptochat.tui e textual vêm de .pyc"`);
