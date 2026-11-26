// The Python program that turns the vendored packages into the precompiled
// zips. Shared by precompile.mjs (Node) and precompile-browser.mjs (Chromium,
// for hosts where the cryptography wheel cannot be imported under Node).
export const COMPILE_PY = `
import gzip, importlib.util, io, os, sys, sysconfig, zipfile
from importlib._bootstrap_external import _code_to_hash_pyc

FIXED = (1980, 1, 1, 0, 0, 0)

def pyc(source_bytes, filename):
    code = compile(source_bytes, filename, "exec", dont_inherit=True, optimize=0)
    return _code_to_hash_pyc(code, importlib.util.source_hash(source_bytes), checked=False)

def add(zf, name, data):
    info = zipfile.ZipInfo(name, FIXED)
    info.compress_type = zf.compression
    info.external_attr = 0o644 << 16
    zf.writestr(info, data)

# 1. the standard library zip, with bytecode next to every module
stdlib = next(p for p in sys.path if p.endswith(".zip"))
used = set()
for mod in list(sys.modules.values()):
    origin = getattr(getattr(mod, "__spec__", None), "origin", None) or ""
    if origin.startswith(stdlib + "/"):
        used.add(origin[len(stdlib) + 1:])
out, rest = io.BytesIO(), io.BytesIO()
n_std = n_core = 0
with zipfile.ZipFile(stdlib) as src, \\
        zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as core_zip, \\
        zipfile.ZipFile(rest, "w", zipfile.ZIP_STORED) as rest_zip:
    for name in sorted(src.namelist()):
        data = src.read(name)
        dst = core_zip if (name in used or not name.endswith(".py")) else rest_zip
        if name.endswith(".py"):
            try:
                add(dst, name[:-3] + ".pyc", pyc(data, os.path.join(stdlib, name)))
                n_std += 1
                n_core += dst is core_zip
                continue                 # sourceless: zipimport loads the .pyc
            except SyntaxError:      # test data and the like: stays source only
                pass
        add(dst, name, data)
# the zips the page fetches itself are stored (no per-file compression) and
# gzipped whole: smaller across files, unpacked natively by the browser
# (DecompressionStream), and Python reads them without inflating in wasm
def gz(data):
    return gzip.compress(data, compresslevel=9, mtime=0)

stdlib_zip, stdlib_rest = out.getvalue(), gz(rest.getvalue())

# 2. site-packages and the app: pure packages whole, compiled ones only their bytecode
site = sysconfig.get_paths()["purelib"]
compiled_tops = set()
for dist in COMPILED_PACKAGES:
    # top-level names installed by loadPackage for the compiled packages
    import importlib.metadata as md
    try:
        files = md.files(dist) or []
    except md.PackageNotFoundError:
        files = []
    for f in files:
        compiled_tops.add(str(f).split("/")[0])
LATER = {"pygments"}      # not needed to open the chat: its own zip, fetched afterwards
out, later = io.BytesIO(), io.BytesIO()
n_site = 0
with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as main_zip, \\
        zipfile.ZipFile(later, "w", zipfile.ZIP_STORED) as later_zip:
    for root, prefix in ((site, site.lstrip("/")), ("/app", "app")):
        for base, dirs, files in sorted(os.walk(root)):
            dirs[:] = sorted(d for d in dirs if d != "__pycache__")
            rel = os.path.relpath(base, root)
            top = rel.split(os.sep)[0]
            only_pyc = root == site and top in compiled_tops
            if root == site and top in LATER:
                dst, arc_root = later_zip, ""          # a zip for zipimport: paths from the package down
            else:
                dst, arc_root = main_zip, None
            for name in sorted(files):
                full = os.path.join(base, name)
                arc = os.path.normpath(os.path.join(prefix if arc_root is None else arc_root, rel, name))
                with open(full, "rb") as fh:
                    data = fh.read()
                if name.endswith(".py"):
                    try:
                        code = pyc(data, full)
                    except SyntaxError:
                        code = None
                    if code is not None:
                        n_site += 1
                        if only_pyc:     # the .py is installed by loadPackage: bytecode in __pycache__
                            tag = sys.implementation.cache_tag
                            add(dst, os.path.join(os.path.dirname(arc), "__pycache__", f"{name[:-3]}.{tag}.pyc"), code)
                        else:            # sourceless module: the .pyc where the .py would be
                            add(dst, arc[:-3] + ".pyc", code)
                        continue
                if not only_pyc:
                    add(dst, arc, data)
site_zip, later_zip = gz(out.getvalue()), gz(later.getvalue())
(stdlib_zip, site_zip, later_zip, stdlib_rest, n_std, n_core, n_site, sorted(compiled_tops))
`;

export function unwrap(result) {
  const [stdlibZip, siteZip, laterZip, stdlibRest, nStd, nCore, nSite, tops] = result.toJs();
  return { stdlibZip, siteZip, laterZip, stdlibRest, nStd, nCore, nSite, tops };
}
