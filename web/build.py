#!/usr/bin/env python3
"""Build web/dist/: the static site of the browser client.

    python3 web/fetch_vendor.py      # once: downloads and verifies vendor/
    (cd web && npm ci)               # once: the build runs Pyodide under Node
    python3 web/build.py             # dist/: the page, the runtime and the bytecode

The page loads Python already compiled (precompile.mjs runs Pyodide's own
Python at build time): py/python_stdlib.zip (the standard library),
py/site.zip (Textual, Rich..., the crptochat package from this repository and
web/py/crptoweb) and py/later.zip (Pygments, fetched once the chat is open).
Every zip is deterministic (fixed dates and order, hash-based .pyc), so the
same commit builds the same bytes. dist/SHA256SUMS lists every file, for
comparing what a host serves with what was built.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DIST = os.path.join(HERE, "dist")
FIXED = (1980, 1, 1, 0, 0, 0)
SKIP_MODULES = {"server.py", "webgate.py", "admin.py", "dash.py", "stats.py", "selftest.py"}   # server side


def app_zip(path: str) -> None:
    entries = []
    for base, pkg in ((ROOT, "crptochat"), (os.path.join(HERE, "py"), "crptoweb")):
        for name in sorted(os.listdir(os.path.join(base, pkg))):
            if name.endswith(".py") and not (pkg == "crptochat" and name in SKIP_MODULES):
                entries.append((f"{pkg}/{name}", os.path.join(base, pkg, name)))
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for arc, src in entries:
            info = zipfile.ZipInfo(arc, FIXED)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            with open(src, "rb") as fh:
                zf.writestr(info, fh.read())


def main() -> int:
    if not os.path.isfile(os.path.join(HERE, "vendor", "manifest.json")):
        print("falta web/vendor/: rode antes python3 web/fetch_vendor.py", file=sys.stderr)
        return 1
    if os.path.isdir(DIST):
        shutil.rmtree(DIST)
    if not os.path.isdir(os.path.join(HERE, "node_modules", "ws")):
        print("falta web/node_modules/: rode antes (cd web && npm ci)", file=sys.stderr)
        return 1
    # Everything but the page and the service worker lives under b/<build id>/: a page
    # of one build can only ever ask for files of that build (at worst a 404 once the
    # host serves another build; never a file of another build).
    stage = os.path.join(DIST, "b", "_")
    shutil.copytree(os.path.join(HERE, "src"), stage, ignore=shutil.ignore_patterns("index.html", "sw.js"))
    vendor = os.path.join(stage, "vendor")
    shutil.copytree(os.path.join(HERE, "vendor"), vendor)
    app = os.path.join(HERE, "app.zip.tmp")
    app_zip(app)
    try:
        # On Windows the cryptography wheel aborts under Node; Chromium (the real
        # target) runs it fine. WEB_PRECOMPILE_BROWSER=1 uses that path for local
        # builds there. CI keeps the default, which does not need a browser.
        tool = "precompile-browser.mjs" if os.environ.get("WEB_PRECOMPILE_BROWSER") else "precompile.mjs"
        subprocess.run(["node", os.path.join(HERE, tool), os.path.join(HERE, "vendor"), app,
                        os.path.join(stage, "py")], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        print("o build precisa do Node 18+ (node no PATH)", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as exc:
        sys.stderr.write(exc.stderr.decode(errors="replace")[-2000:])
        return 1
    finally:
        os.remove(app)
    # what the page no longer fetches: replaced by the precompiled zips
    shutil.rmtree(os.path.join(vendor, "wheels"))
    os.remove(os.path.join(vendor, "pyodide", "python_stdlib.zip"))
    # the build id: a hash of every file of the build
    staged = sorted(os.path.relpath(os.path.join(b, f), stage).replace(os.sep, "/")
                    for b, _d, fs in os.walk(stage) for f in fs)
    digest = hashlib.sha256()
    for rel in staged:
        with open(os.path.join(stage, rel), "rb") as fh:
            digest.update(rel.encode() + b"\0" + hashlib.sha256(fh.read()).digest())
    build_id = digest.hexdigest()[:16]
    base = f"b/{build_id}"
    os.rename(stage, os.path.join(DIST, base))
    with open(os.path.join(HERE, "src", "index.html"), encoding="utf-8") as fh:
        page = fh.read()
    if page.count("__BUILD_DIR__") < 2:   # stylesheet + module script (xterm loads later, from main.js)
        print("src/index.html sem __BUILD_DIR__ nos links", file=sys.stderr)
        return 1
    with open(os.path.join(DIST, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(page.replace("__BUILD_DIR__", base))
    # the service worker caches exactly this build's files, under this build's id
    files = ["index.html"] + [f"{base}/{rel}" for rel in staged]
    with open(os.path.join(HERE, "src", "sw.js"), encoding="utf-8") as fh:
        text = fh.read()
    with open(os.path.join(DIST, "sw.js"), "w", encoding="utf-8") as fh:
        fh.write(text.replace('"__BUILD__"', json.dumps(build_id)).replace("__FILES__", json.dumps(files)))
    sums = []
    for base, _dirs, files in os.walk(DIST):
        for name in files:
            path = os.path.join(base, name)
            with open(path, "rb") as fh:
                sums.append(f"{hashlib.sha256(fh.read()).hexdigest()}  {os.path.relpath(path, DIST)}")
    with open(os.path.join(DIST, "SHA256SUMS"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(sorted(sums, key=lambda s: s.split("  ")[1])) + "\n")
    total = sum(os.path.getsize(os.path.join(b, f)) for b, _d, fs in os.walk(DIST) for f in fs)
    print(f"web/dist/ pronto: build {build_id}, {len(sums)} arquivos, {total / 1e6:.1f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
