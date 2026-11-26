# crptochat no navegador (prova de conceito)

O **mesmo** cliente de terminal (o pacote `crptochat`, com a mesma
criptografia, o mesmo protocolo e a mesma interface Textual) rodando dentro do
navegador. O Python roda em WebAssembly (Pyodide), a interface é desenhada num
xterm.js e a conexão com o servidor usa a entrada WebSocket
(`crptochat-server --ws-port`, veja o README principal).

> **Prova de conceito.** Serve para medir e decidir. Não publique para
> usuários: ainda falta o que está em *Próximos passos*, principalmente a
> parte de integridade de quem serve a página.

## Como funciona

| Peça | Onde |
|---|---|
| Python 3.14 + `cryptography` 47 em WebAssembly | `vendor/pyodide/` (Pyodide 314.0.8) |
| Textual, Rich e dependências (wheels puros) | `vendor/wheels/`, entregues já compilados em `py/site.zip.gz` |
| Python pré-compilado (bytecode) | `py/` no `dist/`, gerado por `precompile.mjs` |
| Terminal na página | `vendor/xterm/` (xterm.js 6) |
| Driver do Textual para o xterm.js | `py/crptoweb/driver.py` |
| Conexão por WebSocket no lugar do TCP | `py/crptoweb/net.py` |
| Login (abre ou cria a chave) e início | `py/crptoweb/boot.py`, `src/main.js` |
| Chaves e preferências | IndexedDB (sistema de arquivos `/data` do Pyodide, sincronizado a cada 3 s e ao sair) |

- **Nada vem de CDN em tempo de execução.** `fetch_vendor.py` baixa tudo uma
  vez e confere cada arquivo contra `vendor.lock.json`: tarballs do npm pelo
  sha512, wheels do PyPI pelo sha256, e os pacotes compilados do Pyodide pelo
  sha256 do `pyodide-lock.json`, que vem do tarball do npm já conferido.
  O `loadPackage` do Pyodide confere de novo o sha256 de cada pacote dele.
- **CSP rígida** na página:
  - `script-src 'self' 'wasm-unsafe-eval'`, então não roda script inline,
    `eval` nem script de outra origem;
  - `connect-src` limitado a `wss:` (e `ws://localhost` para testes);
  - nada de analytics nem fontes externas.
  - Exceção: `style-src` precisa de `'unsafe-inline'`, porque o xterm.js
    aplica estilos inline. Estilo não executa código.
  - **O host precisa mandar cabeçalhos HTTP.** Algumas proteções não valem
    num `<meta>`: o navegador ignora `frame-ancestors` ali. Para a página não
    poder ser embutida noutro site (clickjacking), quem serve o `dist/` precisa
    responder com:

    ```
    Content-Security-Policy: frame-ancestors 'none'
    X-Frame-Options: DENY
    ```

    Vale também mandar a CSP inteira por cabeçalho, além do `<meta>`.
- **Sem pin de certificado no navegador.** O terminal fixa o certificado do
  servidor na primeira conexão (TOFU, `--pin`, `--reset-pin`). O navegador não
  deixa a página fazer isso: o `wss://` é conferido só contra as CAs públicas
  em que o navegador confia, então o servidor precisa de um certificado de CA
  pública. Quem conseguir um certificado válido para o domínio (uma CA
  comprometida, o próprio host) pode se pôr no meio da conexão. Vê os
  **metadados** (quem conecta, quando, tamanhos), mas **não o conteúdo**: a
  cifra de ponta a ponta continua valendo, e uma troca da chave de um contato
  aparece como mudança de fingerprint. Na interface aparece "TLS" para
  `wss://`.
- **`build.py`** gera `dist/`, que é o site estático. O Python chega **já
  compilado**: `precompile.mjs` roda o próprio Python do Pyodide no Node,
  então é a mesma versão e o mesmo bytecode da página. Os `.pyc` são "unchecked
  hash" (PEP 552), sem data e sem conferir a fonte, e não vai fonte junto
  (tracebacks ficam sem as linhas de código):
  - `py/python_stdlib.zip`: só a parte da stdlib que a página importa antes do
    login (1,9 MB em vez de 4,5);
  - `py/site.zip.gz`: Textual, Rich…, `crptochat/` (sem os módulos do servidor)
    e `crptoweb/`;
  - `py/stdlib-rest.zip.gz` e `py/later.zip.gz` (Pygments, só para colorir
    código): baixados em segundo plano enquanto a pessoa digita. O chat só começa
    depois que chegaram, então nunca falta módulo.
  
  Os `.zip.gz` são zips sem compressão interna e comprimidos inteiros. Ficam
  menores e o navegador descomprime nativamente (`DecompressionStream`), sem
  depender de o host comprimir `.zip`.
- **Build determinístico; reprodutível ainda a provar:** datas, ordem e
  bytecode fixos. O CI (`.github/workflows/web.yml`, check "web") builda duas
  vezes no mesmo runner e compara o `SHA256SUMS`, e roda `smoke.mjs`, que
  carrega o `dist/` como a página faz. Isso prova **determinismo** (nada de data,
  ordem ou acaso no resultado), **não** que outra máquina chega aos mesmos bytes.
  Para que isso seja verificável, a toolchain está fixada:
  - Python 3.12.8 e Node 22.12.0 no CI;
  - Pyodide e cada pacote por hash no `vendor.lock.json`;
  - `ws` no `package-lock.json`.
  
  O job imprime o `SHA256SUMS`. Quem quiser conferir builda o mesmo commit com
  as mesmas versões e compara. O bytecode vem do Python do Pyodide (wasm), não
  do Python da máquina, o que ajuda, mas só uma segunda máquina prova.
- **Cada build no seu caminho:** tudo menos `index.html` e `sw.js` fica em
  `b/<id do build>/`, e o id é o hash de todos os arquivos. Uma página só pede
  arquivos do próprio build, então nunca mistura builds: no pior caso recebe
  404, se o host já trocou de build. Os arquivos de `b/` nunca mudam e podem ir
  com cache longo (`Cache-Control: immutable`); `index.html` e `sw.js` não.
- **Service worker (`sw.js`):** guarda os arquivos **deste build** num cache
  com o id do build. Da segunda visita em diante a página abre sem baixar nada,
  e funciona até offline. Um build novo traz um `sw.js` novo, que assume na
  hora e apaga o cache antigo. A página aberta do build antigo:
  - **recarrega** se estiver parada na tela de login (sem senha digitada);
  - senão, mostra "há uma versão nova", e segue no build dela.
  
  Depois que o chat abre, a página não precisa de mais nada da rede. Só
  arquivos do build passam pelo cache; o WebSocket não.
- **Navegador antigo:** sem `DecompressionStream` (Safari antes do 16.4),
  `WebAssembly` ou `IndexedDB`, a página diz qual falta e a versão mínima, em
  vez de quebrar depois.
- **Sem threads no navegador.** `asyncio.to_thread` roda em linha, então o
  scrypt de canal com senha trava a tela por um instante.

## Modo sensível

A caixa **modo sensível** na tela de login é opt-in (desligada por padrão e
lembrada na próxima visita). Ela reduz o que fica no contexto da página:
cada conversa guarda no máximo **200 linhas** decifradas em vez de 3000, o
histórico do campo de texto guarda no máximo **20 linhas**, e ao sair da aba por
mais de 15 s (ou ao fechar/navegar) a interface apaga as linhas, o histórico,
o texto em edição e as mensagens às quais ainda dava para responder/editar.
No mesmo gatilho, o xterm.js limpa o próprio buffer e o scrollback: limpar só
o Textual deixaria as mensagens na rolagem acima da tela. A conexão e o estado
cifrado continuam: só some o que a interface mantinha para desenhar a tela.

O motivo é que a cifra de ponta a ponta protege o fio e o servidor, **não o
contexto onde a mensagem aparece**. Para ser exibida, a mensagem precisa estar
em claro na memória do navegador: nos buffers do Textual e no buffer/DOM do
xterm.js. **Não é o IndexedDB** — ali ficam só chaves e preferências; as
mensagens descriptografadas não são gravadas lá. Foi justamente lendo
`window.crptoTerm.buffer` que se confirmou o plaintext na tela. Qualquer script
que rode naquela página — ou uma extensão com acesso a ela — pode fazer o mesmo.
Antes, o xterm.js era exposto como `window.crptoTerm`, o que tornava essa leitura
trivial; o objeto não é mais publicado. Isso não impede leitura por depurador ou
código que já roda na página: apenas encurta a janela e remove o atalho. Não use
o cliente web numa origem de que você não confie.

`CRPTOCHAT_SENSITIVE=1` ativa o modo fora da página, e `CRPTOCHAT_LOG_LINES`
ajusta o limite (50 a 3000) para quem quiser outro valor no cliente de terminal.
O modo sensível não apaga cópias que outra pessoa tenha, nem o que o servidor
guarda cifrado.

## Chaves e cofres de senha

O navegador não roda `pass`, `secret-tool` nem `vault` como o terminal. A
integração passa então pelo que os cofres já fazem no navegador:

- **Senha da chave no gerenciador de senhas.** O formulário segue o que os
  gerenciadores procuram: nick como usuário (`autocomplete="username"`),
  senha da chave como senha (`current-password` / `new-password` ao criar), e —
  quando a chave ainda não está neste navegador — o campo **chave cifrada
  (JSON)** (`name="crptochat_identity"`) para o blob do terminal ou do anexo no
  1Password. O JSON fica cifrado; a página só o grava no navegador depois de
  conferir a senha, e apaga o campo ao importar (não vai para
  `localStorage`). No 1Password: item *Login* com usuário = nick, senha = frase
  da chave, e campo personalizado ou nota com o JSON (o mesmo de
  `identities/nick.json` ou `pass show crptochat/NICK`). **Pedir para guardar** a
  senha (Credential Management API, só no Chromium) é **opt-in**: a caixa
  "pedir ao navegador para guardar esta senha" vem desmarcada. Senha e backup da
  chave no mesmo gerenciador deixam o gerenciador como a única proteção. O
  navegador ou a extensão também podem oferecer por conta própria; a página
  avisa que basta recusar.
- **A chave no cofre, para backup e para levar entre aparelhos.** "Exportar /
  backup" dá o **mesmo blob** que o terminal guarda no cofre: a semente Ed25519
  já cifrada com a senha (scrypt + ChaCha20-Poly1305, presa ao nick). Ele é
  baixado como arquivo ou copiado, e vai no gerenciador como nota segura ou
  anexo, ou no `pass insert -m crptochat/NICK`. "Importar chave" aceita
  esse blob, o arquivo `~/.config/crptochat/NICK.json` do terminal ou a saída
  de `pass show crptochat/NICK`. A senha é conferida no navegador antes de
  guardar. Uma chave diferente para o mesmo nick só é substituída se a pessoa
  marcar "substituir" **e** confirmar num segundo passo, que diz que a chave
  atual será apagada de vez e oferece exportá-la antes. Se a chave importada
  for a mesma que já está aqui, nada é apagado e não há confirmação.
- **Backup obrigatório ao criar uma chave:** antes de abrir o chat aparece o
  painel de backup, porque a chave existe só naquele navegador. No iPhone o
  Safari pode apagar os dados do site.

Quem pegar o blob ainda precisa da senha. Guardar os dois no mesmo cofre deixa
o cofre como a única proteção, igual a usar `--pass-cmd` no terminal.

Ainda não: desbloquear com Face ID ou digital (passkey com a extensão PRF do
WebAuthn), e mover a chave por dentro do chat (o "Mover minha chave" do menu
chama programas locais e não funciona no navegador).

## Rodar localmente

```sh
python3 web/fetch_vendor.py          # baixa e confere web/vendor/ (~19 MB)
(cd web && npm ci)                   # o build roda o Pyodide no Node (precisa do Node 18+)
python3 web/build.py                 # gera web/dist/ (build de produção, reprodutível)
node web/smoke.mjs                   # opcional: confere o build (Pyodide no Node)
node web/e2e.mjs                     # opcional: ponta a ponta no Chromium (precisa do crptochat instalado)

# servidor com a entrada WebSocket, aceitando a página servida em localhost:8123
crptochat-server --no-tls --ws-port 7778 --ws-origin http://localhost:8123

# servir web/dist (precisa do tipo certo para .mjs e .wasm; o http.server do Python 3.13 já serve)
python3 -m http.server 8123 --bind 127.0.0.1 --directory web/dist
```

Para iterar sem esperar pela pré-compilação (muda `.py`, roda de novo), use o
build de desenvolvimento:

```sh
python3 web/build_dev.py             # gera web/dist-dev/, sem Node e sem precompile.mjs
python3 -m http.server 8124 --bind 127.0.0.1 --directory web/dist-dev
```

Ele entrega o Python em fonte, com a stdlib inteira: é maior e mais lento, e o
resultado não é reprodutível. Serve só para desenvolvimento local — não publique
`dist-dev/`. Ele grava apenas em `web/dist-dev/` (incluído no `.gitignore`) e
nunca apaga nem substitui `web/dist/`, que continua sendo o build de produção
gerado por `build.py` (com `SHA256SUMS` e bytecode pré-compilado). O
`dist-dev/` também tem `SHA256SUMS` e um `sw.js` com a lista de arquivos do
build, para o service worker trocar de build quando o código muda.

Abra `http://localhost:8123`, informe `ws://localhost:7778`, um nick e uma
senha. Em produção o endereço é `wss://`, com certificado de CA pública.

## O que a PoC mostrou

Testado com Chromium headless (Playwright), contra um servidor local:

| | Resultado |
|---|---|
| Carregamento no desktop (sem limitação) | **~1,5 s** até o botão "entrar" (era ~5 s antes do bytecode pré-compilado) |
| Login até ONLINE | < 1 s |
| DM navegador → terminal e terminal → navegador | **funciona**, cifrada de ponta a ponta, decifrada pelo cliente de terminal de verdade |
| Chave no IndexedDB | sobrevive a recarregar; senha errada é recusada; a mesma chave é aceita pelo servidor |
| Memória | ~80 MB de memória do WebAssembly + ~20 MB de heap JS |
| Transferido até poder entrar | ~11 MB com gzip (o wasm é 3,5 MB); mais ~4 MB em segundo plano |
| Celular emulado (Pixel 7, CPU 4× mais lenta), **sem limitar a rede** | **22,8 s → 7,2 s** |
| Celular emulado, CPU 4× + **4G de 9 Mbit/s**, primeiro acesso | **42 s → 14,5 s** (agora limitado pela banda) |
| Idem, **visitas seguintes** (service worker) | **33 s → 6,1 s**, sem baixar nada |
| Layout em tela de celular | resolvido no PR da TUI estreita (#21) |

De onde veio o ganho, no perfil com CPU 4× (`imports` é o `import` do
crptochat e do Textual):

| Fase | Antes | Depois |
|---|---|---|
| iniciar o Python | 10,5 s | 3,1 s (stdlib já compilada) |
| imports | ~10 s | ~2,2 s (bytecode pronto) |
| pacotes | 2,9 s | 1,0 s (só o `cryptography`; o resto vem no `site.zip.gz`) |

Achado que virou correção no cliente principal: o `cryptography` do Pyodide
tem o módulo ML-KEM, mas o OpenSSL dele não tem o algoritmo. O
`crypto.HAS_MLKEM` agora testa gerando uma chave, não só importando. No
navegador, por enquanto, **não há a camada pós-quântica** (fica só o X25519,
como nos clientes com `cryptography` < 47). A negociação de capacidades (`pq`)
já trata isso com os outros clientes.

## Limitações conhecidas

- Sem camada pós-quântica (acima).
- Transferência P2P de arquivos e mensagens de voz não funcionam (precisam de
  socket e de ffmpeg); arquivos pelo servidor devem funcionar, mas não testei.
- `/update` não se aplica: quem atualiza é o site.
- Não testado em Safari/iOS de verdade, nem em Firefox.

## Próximos passos

1. **Velocidade**: o login deixou de carregar xterm.js e Textual — medição
   antes/depois e mapa de % em [PERF.md](PERF.md) (CPU 4×: 6,2 s → 4,4 s até o
   botão “entrar”). Falta medir num celular de verdade. Se ainda pesar, os
   próximos passos são o snapshot de memória do Pyodide (API privada,
   experimental; carregaria o Python já inicializado, guardado no aparelho
   depois da primeira visita) e diminuir o primeiro download, que hoje é
   limitado pela banda (`pyodide.asm.wasm`).
2. ~~Layout estreito na TUI~~: PR #21.
3. **Publicação** (só com isto pronto):
   - ~~build reproduzível no CI~~ (`web.yml`);
   - manifesto assinado na release;
   - hospedagem fora do servidor do chat;
   - monitor externo comparando o que é servido com a release;
   - página "verificar esta instalação".
4. Aviso de "adicione à tela inicial" no iOS antes de criar a chave, e
   desbloqueio por passkey (PRF) como atalho opcional.
