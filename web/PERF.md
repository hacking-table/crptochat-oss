# Mapa de melhoria — cliente web

Medição **antes/depois** do mesmo build de produção (`web/dist/`), com o mesmo
harness (`web/perf.mjs`), antes de abrir qualquer PR. Nada aqui é estimativa:
cada número é a mediana de 5 carregamentos frios num Chromium headless, contexto
novo por execução, service worker bloqueado, servidor local com gzip. O perfil
`cpu4` usa `Emulation.setCPUThrottlingRate({rate:4})`, o mesmo usado no
[roadmap do README](README.md#próximos-passos) para celular.

| | Antes (`8f383c2`) | Depois (`claude/web-perf`) |
|---|---|---|
| Botão “entrar” pronto — desktop | 1289 ms | 1044 ms |
| Botão “entrar” pronto — CPU 4× | 6193 ms | 4403 ms |
| Fim do carregamento (`wall`) — CPU 4× | 6339 ms | 4837 ms |
| Fase após os pacotes (unzip + imports) — CPU 4× | 3042 ms | 941 ms |
| JS baixado antes do login | 1598 KB | 1260 KB |
| CSS antes do login | 13 KB | 6 KB |
| Arquivos JS antes do login | 5 | 3 |

Dados brutos: [`perf-baseline-cpu1.json`](perf-baseline-cpu1.json),
[`perf-after-cpu1.json`](perf-after-cpu1.json),
[`perf-baseline-cpu4.json`](perf-baseline-cpu4.json),
[`perf-after-cpu4.json`](perf-after-cpu4.json). Para reproduzir o mapa:

```sh
node web/perf.mjs --map web/perf-baseline-cpu4.json web/perf-after-cpu4.json
```

## Mapa de % de melhoria

🟩🟩🟩 ≥ 50% · 🟩🟩 20–49% · 🟩 5–19% · ⬜ 0–5% · 🟥 piorou/ruído

| Métrica | CPU 1× | CPU 4× | Mapa (4×) |
|---|---:|---:|:---:|
| Fase unzip + imports | +69,3% | +69,1% | 🟩🟩🟩 |
| CSS no caminho do login | +53,8% | +53,8% | 🟩🟩🟩 |
| Arquivos JS no caminho do login | +40,0% | +40,0% | 🟩🟩 |
| Tempo até o botão “entrar” | +19,0% | +28,9% | 🟩🟩 |
| Tempo total de carregamento | +15,1% | +23,7% | 🟩🟩 |
| `TaskDuration` do renderer | +19,8% | +23,7% | 🟩🟩 |
| JS decodificado antes do login | +21,2% | +21,2% | 🟩🟩 |
| FCP | +15,8% | 0,0% | ⬜ |
| Bytes transferidos antes do login | +0,8% | +0,7% | ⬜ |
| Boot do Pyodide | +0,8% | −8,9% | 🟥 |
| Carregamento de pacotes | −0,8% | −8,1% | 🟥 |
| Heap JS | −9,0% | −9,0% | 🟥 |

Os números negativos são ruído entre execuções (o boot do Pyodide e o wheel de
`cryptography` não foram alterados) e o aumento de heap é esperado: o xterm
passa a ser alocado no clique de “entrar”, não no boot. O ganho de bytes
transferidos é pequeno porque `pyodide.asm.wasm` domina o download; o que caiu
foi o **JS/critical path**, não a banda total.

## O que mudou

1. `web/src/main.js`: `xterm.mjs` e `addon-fit.mjs` saíram dos imports estáticos
   e passam a ser carregados por `import()` em `launch()`. O CSS do xterm também
   deixa de ser `<link>` no `<head>` e é injetado no mesmo momento. Quem abre a
   página e nunca entra no chat não baixa nem analisa esses 338 KB (+7 KB de
   CSS); quem entra paga o custo depois de o login já estar utilizável.
2. `web/py/crptoweb/boot.py`: `from . import driver` (que importa Textual, Rich e
   o parser de terminal) saiu do import do módulo e foi para `start()`. O
   `main.js` agora importa só `crptoweb.boot` antes do login; `crptochat.tui`
   entra junto com o driver, quando o chat abre. É daí que vem o ganho de ~69%
   na fase posterior aos pacotes.
3. `web/build.py`, `web/smoke.mjs`: ajustes no contrato do build (dois
   `__BUILD_DIR__` em vez de três; xterm conferido no `main.js`) e na abertura
   UTF-8 dos arquivos de texto, necessária no Windows.
4. `web/precompile.mjs` → `web/precompile-core.mjs`: o programa de pré-compilação
   virou módulo compartilhado. Ele continua importando boot + tui para classificar
   a stdlib, mas agora também pode rodar dentro do Chromium
   (`web/precompile-browser.mjs`) — no Windows o wheel de `cryptography` aborta
   sob Node, enquanto no navegador (o alvo real) funciona.

## Como reproduzir do zero

```sh
# no Linux (CI), o build normal; no Windows, use o caminho alternativo:
python web/build.py
# WEB_PRECOMPILE_BROWSER=1 python web/build.py

node web/perf.mjs --label baseline --runs 5 --cpu 4 --out web/perf-baseline-cpu4.json
# ...aplique a mudança, rode build.py de novo...
node web/perf.mjs --label after --runs 5 --cpu 4 --out web/perf-after-cpu4.json
node web/perf.mjs --map web/perf-baseline-cpu4.json web/perf-after-cpu4.json
```

Limitações: servidor em `localhost` (sem latência de rede real), Chromium em vez
de Safari/iOS, e nenhum celular físico. O próximo passo do roadmap — medir num
aparelho — continua pendente; aqui o que se mediu foi o mesmo cenário antes e
depois, com CPU limitada a 4×.
