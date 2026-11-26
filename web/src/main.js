// crptochat no navegador: carrega o Python (Pyodide) e o cliente de sempre, e
// desenha a interface Textual num xterm.js. Tudo vem desta mesma origem
// (b/<build>/vendor e b/<build>/py); nada de CDN, nada de script de terceiros.
// O Python chega já compilado (py/*.zip, gerados por precompile.mjs no build).
import { loadPyodide } from "./vendor/pyodide/pyodide.mjs";
// xterm.js is only needed after the login. Importing it here would put ~350 KB
// of JavaScript on the critical path of the login page, which most visitors
// never get past while Python is still starting. loadTerminal() fetches it in
// launch(), together with the rest that the chat needs.
let terminalModule = null;
const loadTerminal = () => terminalModule ??= Promise.all([
  import("./vendor/xterm/xterm.mjs"), import("./vendor/xterm/addon-fit.mjs"),
]).then(([xterm, fit]) => ({ Terminal: xterm.Terminal, FitAddon: fit.FitAddon }));

const $ = (id) => document.getElementById(id);
const status = (text, err = false) => { $("status").textContent = text; $("status").classList.toggle("err", err); };
const t0 = performance.now();
const marks = {};
const mark = (name) => { marks[name] = Math.round(performance.now() - t0); };
window.crptoMetrics = marks;

const remember = (k, v) => { try { v === undefined ? (v = localStorage.getItem(k)) : localStorage.setItem(k, v); } catch { v = null; } return v; };

function defaultWsUrl() {
  const host = location.hostname;
  if (host === "localhost" || host === "127.0.0.1") return "ws://localhost:7778";
  if (location.protocol === "https:") return `wss://${location.host}/ws`;
  return "";
}

$("url").value = remember("crpto.url") || defaultWsUrl();
$("nick").value = remember("crpto.nick") || "";
$("sensitive").checked = remember("crpto.sensitive") === "1";

async function syncfs(py, populate) {
  return new Promise((ok, fail) => py.FS.syncfs(populate, (err) => (err ? fail(err) : ok())));
}

// Every file of this build is under the build's own directory (b/<id>/, where this
// script is): resolved from here, a page never asks for a file of another build.
const here = (p) => new URL(p, import.meta.url).href;

// Next visits (and offline) open from this build's cache: see sw.js. When a newer
// build's service worker takes over this page (a deploy happened), reload while still
// on the login screen, so the person gets the new build whole. Once the chat runs,
// the page needs nothing else from the network, so it is left alone.
let chatStarted = false;
const idle = () => !chatStarted && !$("form").hidden && !$("pass").value && !$("pass2").value;
if ("serviceWorker" in navigator && window.isSecureContext) {
  const hadController = !!navigator.serviceWorker.controller;   // first visit: nothing to replace
  navigator.serviceWorker.addEventListener("controllerchange", () => {
    if (!hadController) return;
    if (idle()) location.reload();
    // in the middle of something (a key being made, a backup, the chat): not now. This page
    // keeps asking only for its own build's files; if the host no longer has them, it fails
    // with a message instead of mixing builds.
    else if (!chatStarted) status("há uma versão nova: recarregue a página quando terminar");
  });
  navigator.serviceWorker.register(new URL("sw.js", document.baseURI), { scope: "./" }).catch(() => {});
}

// py/*.zip.gz: a zip gzipped whole by the build; the browser inflates it natively
async function fetchGz(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${url}: ${r.status}`);
  return new Response(r.body.pipeThrough(new DecompressionStream("gzip"))).arrayBuffer();
}

// What the page cannot work without. Safari before 16.4 (iOS 16.4) has no
// DecompressionStream, which unpacks py/*.zip.gz: say so plainly instead of failing later.
function missingFeatures() {
  const need = { DecompressionStream: "DecompressionStream", WebAssembly: "WebAssembly", indexedDB: "IndexedDB" };
  return Object.entries(need).filter(([k]) => !(k in window)).map(([, v]) => v);
}

async function boot() {
  const missing = missingFeatures();
  if (missing.length) {
    throw new Error(`este navegador não tem ${missing.join(", ")}. Atualize o navegador ` +
                    "(no iPhone/iPad: iOS 16.4 ou mais novo; Safari 16.4+; Chrome/Edge 80+; Firefox 113+).");
  }
  // downloads start together; the bytecode is unpacked once Python is up
  const site = fetchGz(here("py/site.zip.gz"));
  const py = await loadPyodide({ indexURL: here("vendor/pyodide/"), stdLibURL: here("py/python_stdlib.zip"), fullStdLib: false });
  mark("pyodide");
  status("carregando a criptografia…");
  await py.loadPackage(["cryptography"], { checkIntegrity: true, messageCallback: () => {} });
  mark("packages");
  status("carregando o crptochat…");
  py.unpackArchive(await site, "zip", { extractDir: "/" });     // Textual, Rich… e /app (crptochat, crptoweb)
  py.FS.mkdirTree("/data");
  py.FS.mount(py.FS.filesystems.IDBFS, {}, "/data");
  await syncfs(py, true);                                  // chaves e preferências salvas antes
  py.runPython("import sys, importlib; sys.path.insert(0, '/app'); importlib.invalidate_caches()");
  extras(py).catch(() => {});                              // starts now, in the background
  try {
    await py.runPythonAsync("import crptoweb.boot");        // leve: Textual vem só depois do login
  } catch (err) {
    if (!/ModuleNotFoundError/.test(String(err))) throw err;
    await extras(py);                                      // something outside the boot set: wait for the rest
    await py.runPythonAsync("import crptoweb.boot");
  }
  mark("ready");
  return py;
}

// What Python does not need to open the page: the rest of the standard library
// (stdlib-rest.zip.gz) and Pygments (later.zip.gz, only for colouring code). Fetched
// in the background as soon as the page is up, imported straight from the zips,
// and always in place before the chat starts (launch waits for it).
// A failure (the network went away) is not kept: the next call tries again.
let extrasPromise = null;
function extras(py) {
  extrasPromise ??= (async () => {
    for (const name of ["stdlib-rest.zip", "later.zip"]) {
      py.FS.writeFile("/lib/" + name, new Uint8Array(await fetchGz(here(`py/${name}.gz`))));
      // also for packages already imported from the boot zip (crptoweb/mount.py)
      py.runPython(`import crptoweb.mount; crptoweb.mount.mount('/lib/${name}')`);
    }
    mark("extras");
  })().catch((err) => { extrasPromise = null; throw err; });
  return extrasPromise;
}

function terminalBridge(term) {
  let onData = null, onResize = null, onHide = null, hideTimer = null;
  const keys = { esc: "\x1b", tab: "\t", up: "\x1b[A", down: "\x1b[B", right: "\x1b[C", left: "\x1b[D",
                 slash: "/", pgup: "\x1b[5~", pgdn: "\x1b[6~", nl: "\n" };     // nl: new line (Ctrl+J)
  // Shift+Enter: a new line in the message box, not send. xterm.js would send a
  // plain \r; send what a terminal with the kitty keyboard protocol sends
  // (Textual reads it as shift+enter).
  term.attachCustomKeyEventHandler((e) => {
    if (e.key !== "Enter" || !e.shiftKey || e.ctrlKey || e.altKey || e.metaKey) return true;
    if (e.type === "keydown") onData && onData("\x1b[13;2u");
    return false;
  });
  let ctrl = false;
  term.onData((d) => {
    if (ctrl && d.length === 1) { const c = d.toUpperCase().charCodeAt(0); if (c >= 64 && c < 96) d = String.fromCharCode(c - 64); }
    ctrl = false; $("keys").querySelector("[data-k=ctrl]").classList.remove("on");
    onData && onData(d);
  });
  term.onResize(({ cols, rows }) => onResize && onResize(cols, rows));
  $("keys").addEventListener("click", (e) => {
    const k = e.target.dataset && e.target.dataset.k; if (!k) return;
    e.preventDefault();
    if (k === "ctrl") { ctrl = !ctrl; e.target.classList.toggle("on", ctrl); }
    else onData && onData(keys[k]);
    term.focus();
  });
  // Sensitive sessions ask Python to wipe decrypted lines when the page is
  // left. A short delay spares a quick Alt-Tab; closing/navigating wipes now.
  // term.clear() drops xterm's own buffer and scrollback: clearing only the
  // Textual buffers would leave the same plaintext in the scroll above the app.
  const hideNow = () => {
    term.clear();
    onHide();
  };
  document.addEventListener("visibilitychange", () => {
    if (!onHide) return;
    if (document.visibilityState === "hidden") {
      if (hideTimer) clearTimeout(hideTimer);
      hideTimer = setTimeout(() => { hideTimer = null; hideNow(); }, 15000);
    } else if (hideTimer) {
      clearTimeout(hideTimer); hideTimer = null;
    }
  });
  addEventListener("pagehide", () => {
    if (!onHide) return;
    if (hideTimer) { clearTimeout(hideTimer); hideTimer = null; }
    hideNow();
  });
  return {
    write: (data) => term.write(data),
    size: () => [term.cols, term.rows],
    set_handlers: (data, resize) => { onData = data; onResize = resize; },
    set_hide_handler: (cb) => { onHide = cb; },
  };
}

let keys = null;                       // crptoweb.keys (Python), once loaded
const tick = () => new Promise((ok) => setTimeout(ok, 30));   // lets "working…" paint before scrypt

function pyMessage(err) {
  const text = String((err && err.message) || err);
  const m = text.match(/KeyProblem: ([^\n]*)\s*$/) || text.match(/Error: ([^\n]*)\s*$/);
  return m ? m[1].trim() : text.split("\n").filter(Boolean).pop();
}

function call(fn, ...args) {
  try {
    const out = keys[fn](...args);
    return out && out.toJs ? out.toJs({ dict_converter: Object.fromEntries }) : out;
  } catch (err) {
    throw new Error(pyMessage(err));
  }
}

const ready = boot().then((py) => {
  py.runPython("import crptoweb.boot; crptoweb.boot.prepare()");
  keys = py.pyimport("crptoweb.keys");
  status(`pronto em ${(marks.ready / 1000).toFixed(1)} s`);
  $("go").disabled = false;
  $("open-import").disabled = false;
  refreshMode();
  return py;
}).catch((err) => { status("falha ao carregar: " + (err.message || err), true); throw err; });

// ------------------------------------------------ new key or existing one

const nickOk = (nick) => /^[A-Za-z0-9_-]{3,20}$/.test(nick);
let creating = false;

function refreshMode() {
  const anon = $("anon").checked, nick = $("nick").value.trim();
  $("nick").disabled = $("pass").disabled = anon;
  const has = !anon && keys && nickOk(nick) && call("has_key", nick);
  creating = !anon && !!keys && nickOk(nick) && !has;
  // what password managers read: a new key asks for a new password (they offer to generate one)
  $("pass").autocomplete = creating ? "new-password" : "current-password";
  $("pass2-row").hidden = !creating;
  $("pass2").required = creating;
  $("blob-row").hidden = anon || !creating;
  $("open-export").disabled = !has;
  $("go").textContent = anon ? "entrar anônimo" : creating ? "criar chave e entrar" : "entrar";
  const info = $("keyinfo");
  info.classList.remove("err");
  info.textContent = anon || !nickOk(nick) ? "" : has
    ? `a chave de ${nick} está neste navegador`
    : creating
      ? `${nick} não tem chave neste navegador: cole o JSON do cofre (ou use "importar chave"), ou crie uma nova.`
      : "";
}
$("nick").addEventListener("input", refreshMode);
$("anon").addEventListener("change", refreshMode);

// Asks the browser's password manager to keep nick + key passphrase (Chromium), only when
// the person ticked "pedir ao navegador para guardar esta senha" (off by default): the
// passphrase and the backup of the key in the same manager leave it as the only protection.
function offerToSave(nick, pass) {
  if (!$("save-pw").checked) return;
  if (!("PasswordCredential" in window) || !navigator.credentials) return;
  try {
    navigator.credentials.store(new PasswordCredential({ id: nick, password: pass, name: `${nick} · crptochat` }))
      .catch(() => {});
  } catch { /* not allowed here */ }
}

// ------------------------------------------------------- export / backup

function showPanel(id) {
  for (const p of ["import", "export"]) $(p).hidden = p !== id;
  $("form").hidden = !!id;
  if (id) $(id).scrollIntoView({ block: "start" });
}
for (const b of document.querySelectorAll("[data-close]")) b.addEventListener("click", () => { showPanel(null); refreshMode(); });

let exported = { nick: "", text: "" };
let afterBackup = null;                // set when the backup panel was opened right after creating a key

function openExport(nick, fingerprint, isNew) {
  exported = { nick, text: call("export_key", nick) };
  $("exp-title").textContent = isNew ? `chave de ${nick} criada: faça o backup agora` : `backup da chave de ${nick}`;
  $("exp-why").textContent = isNew
    ? "Ela existe só neste navegador. Se os dados do site forem apagados (no iPhone o Safari pode fazer isso sozinho) e não houver backup, este nick nunca mais poderá ser usado."
    : "";
  $("exp-pass").textContent = `pass insert -m crptochat/${nick.toLowerCase()}`;
  $("exp-fp").textContent = fingerprint ? `fingerprint ${fingerprint}` : "";
  $("exp-done").textContent = isNew ? "continuar para o chat" : "fechar";
  $("exp-status").textContent = "";
  showPanel("export");
}

$("open-export").addEventListener("click", () => {
  try { openExport($("nick").value.trim(), "", false); } catch (err) { status(err.message, true); }
});

function download(nick, text) {
  const url = URL.createObjectURL(new Blob([text + "\n"], { type: "application/json" }));
  const a = Object.assign(document.createElement("a"), { href: url, download: `crptochat-${nick.toLowerCase()}.json` });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

$("exp-download").addEventListener("click", () => {
  download(exported.nick, exported.text);
  $("exp-status").className = "hint ok"; $("exp-status").textContent = "arquivo baixado: guarde-o no cofre e apague a cópia solta";
});

$("exp-copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(exported.text);
    $("exp-status").className = "hint ok"; $("exp-status").textContent = "copiada: cole no cofre (nota segura) e depois copie outra coisa por cima";
  } catch {
    $("exp-status").className = "hint err"; $("exp-status").textContent = "o navegador não deixou copiar; use \"baixar arquivo\"";
  }
});

$("exp-done").addEventListener("click", () => { if (afterBackup) { const go = afterBackup; afterBackup = null; go(); } });

// ------------------------------------------------------------- import

$("open-import").addEventListener("click", () => { $("imp-status").textContent = ""; showPanel("import"); });

async function importText() {
  let text = $("imp-text").value;
  const file = $("imp-file").files[0];
  if (file) {
    if (file.size > 4096) throw new Error("arquivo grande demais para ser uma chave");
    text = await file.text();
  }
  return text;
}

function importFromBlob(text, pass, replace) {
  const got = call("import_key", text, pass, replace);
  const nick = got.nick;
  $("nick").value = nick;
  remember("crpto.nick", nick);
  return got;
}

async function doImport(text, replace) {
  const py = await ready, st = $("imp-status");
  const got = importFromBlob(text, $("imp-pass").value, replace);
  await syncfs(py, false);
  $("imp-confirm").hidden = true;
  st.className = "hint ok"; st.textContent = `chave de ${got.nick} importada · fingerprint ${got.fingerprint}`;
  $("imp-text").value = ""; $("imp-pass").value = ""; $("imp-file").value = ""; $("key-blob").value = "";
  $("imp-replace").checked = false;
  remember("crpto.nick", got.nick);
}

let pendingReplace = null;             // the blob waiting for "apagar a atual e importar"

$("imp-go").addEventListener("click", async () => {
  const st = $("imp-status");
  $("imp-confirm").hidden = true; pendingReplace = null;
  st.className = "hint"; st.textContent = "conferindo a senha…"; await tick();
  try {
    const text = await importText();
    try {
      await doImport(text, false);       // the same key (or no key here): nothing is lost
    } catch (err) {
      const nick = call("parse_blob", text).nick;
      if (!$("imp-replace").checked || !call("has_key", nick) || !/substituir/.test(err.message)) throw err;
      // replacing destroys the key kept here: one more, explicit step, with a way out
      pendingReplace = { text, nick };
      st.className = "hint"; st.textContent = "";
      $("imp-confirm-text").textContent =
        `A chave de ${nick} que está neste navegador será APAGADA de vez e trocada pela importada. ` +
        `Se ela não tiver backup, o que ela registrou (o nick ${nick} neste servidor) fica inacessível. ` +
        `Exporte a atual antes, se ainda não exportou.`;
      $("imp-confirm").hidden = false;
    }
  } catch (err) {
    st.className = "hint err"; st.textContent = err.message;
  }
});

$("imp-export-current").addEventListener("click", () => {
  if (!pendingReplace) return;
  try {
    download(pendingReplace.nick, call("export_key", pendingReplace.nick));
    $("imp-status").className = "hint ok";
    $("imp-status").textContent = `chave atual de ${pendingReplace.nick} exportada; guarde o arquivo antes de continuar`;
  } catch (err) { $("imp-status").className = "hint err"; $("imp-status").textContent = err.message; }
});

$("imp-confirm-go").addEventListener("click", async () => {
  if (!pendingReplace) return;
  const { text } = pendingReplace;
  pendingReplace = null;
  try { await doImport(text, true); } catch (err) { $("imp-status").className = "hint err"; $("imp-status").textContent = err.message; }
});

$("imp-confirm-cancel").addEventListener("click", () => {
  pendingReplace = null; $("imp-confirm").hidden = true;
  $("imp-status").className = "hint"; $("imp-status").textContent = "nada foi alterado";
});

// -------------------------------------------------------------- login

$("form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const py = await ready;
  const url = $("url").value.trim(), nick = $("nick").value.trim(), pass = $("pass").value,
        anon = $("anon").checked, sensitive = $("sensitive").checked;
  remember("crpto.sensitive", sensitive ? "1" : "0");
  const info = $("keyinfo"), isNew = creating;
  if (!anon) {
    if (isNew && pass !== $("pass2").value) { info.className = "hint err"; info.textContent = "as senhas não conferem"; return; }
    $("go").disabled = true; status(isNew ? "criando a chave…" : "abrindo a chave…"); await tick();
    let opened, brandNew = false;
    try {
      const blob = $("key-blob").value.trim();
      if (blob) {
        const parsed = call("parse_blob", blob);
        if (parsed.nick.toLowerCase() !== nick.toLowerCase()) {
          throw new Error(`o JSON é da chave de ${parsed.nick}, não de ${nick}`);
        }
        status("importando a chave do cofre…"); await tick();
        opened = importFromBlob(blob, pass, false);
        $("key-blob").value = "";
        creating = false;
        refreshMode();
      } else if (isNew) {
        opened = call("create_key", nick, pass);
        brandNew = true;
      } else {
        opened = call("check_passphrase", nick, pass);
      }
    } catch (err) {
      info.className = "hint err"; info.textContent = err.message; status(""); $("go").disabled = false; return;
    }
    offerToSave(nick, pass);
    await syncfs(py, false);
    refreshMode();                       // the key exists now: clears old warnings, enables export
    if (brandNew) {                      // no chat before the backup is offered
      afterBackup = () => launch(py, url, nick, pass, anon, sensitive);
      status("");
      openExport(nick, opened.fingerprint, true);
      return;
    }
  }
  launch(py, url, nick, pass, anon, sensitive);
});

async function launch(py, url, nick, pass, anon, sensitive) {
  remember("crpto.url", url); if (!anon) remember("crpto.nick", nick);
  $("go").disabled = true; status("carregando o resto…");
  try { await extras(py); } catch (err) { status("falha ao carregar: " + err.message, true); $("go").disabled = false; return; }
  status("conectando…");
  // Now, and not before: the login page needs neither the xterm code nor its
  // stylesheet. Both come from this build's own directory (see here()).
  const [{ Terminal, FitAddon }] = await Promise.all([
    loadTerminal(),
    new Promise((ok, fail) => {
      if (document.querySelector("link[data-xterm]")) return ok();
      const link = document.createElement("link");
      link.rel = "stylesheet"; link.href = here("vendor/xterm/xterm.css"); link.dataset.xterm = "1";
      link.onload = ok; link.onerror = fail;
      document.head.append(link);
    }),
  ]);
  chatStarted = true;
  $("login").hidden = true; $("term").hidden = false; $("keys").hidden = false;
  const term = new Terminal({ fontFamily: 'ui-monospace, "SF Mono", Menlo, Consolas, monospace', fontSize: 14,
                              cursorBlink: false, allowProposedApi: false, scrollback: 0,
                              theme: { background: "#0b0b12" } });
  const fit = new FitAddon();
  term.loadAddon(fit);
  term.open($("term"));
  fit.fit();
  new ResizeObserver(() => fit.fit()).observe($("term"));
  term.focus();
  const saver = setInterval(() => syncfs(py, false).catch(() => {}), 3000);
  addEventListener("pagehide", () => syncfs(py, false).catch(() => {}));
  const start = py.globals.get("__import__")("crptoweb.boot").boot.start;
  mark("login");
  // The terminal handle stays local: window.crptoTerm exposed decrypted lines
  // in the xterm buffer/DOM to any script running in this page.
  try {
    const why = await start(terminalBridge(term), url, nick, pass, anon, sensitive);
    term.reset(); term.write("\r\n  " + why + "\r\n  recarregue a página para entrar de novo.\r\n");
  } catch (err) {
    term.write("\r\n\x1b[31m  " + String(err).split("\n").slice(-2).join(" ") + "\x1b[0m\r\n  recarregue a página para tentar de novo.\r\n");
  } finally {
    clearInterval(saver);
    await syncfs(py, false).catch(() => {});
  }
}
