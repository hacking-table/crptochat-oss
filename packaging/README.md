# Empacotamento do cliente

Gera o binário do **cliente** (TUI) com PyInstaller, sem incluir o servidor nem o painel.

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install . pyinstaller
pyinstaller --noconfirm --clean packaging/crptochat.spec
# resultado: dist/crptochat  (ou dist/crptochat.exe no Windows)
```

O workflow `.github/workflows/release-client.yml` roda a cada mudança do cliente no `main`: compila, testa o binário de verdade (`packaging/smoke_binary.py`) e atualiza a release mais recente do repositório privado `hacking-table/crptochat-client`, junto com `SHA256SUMS` e o instalador `install.sh`. Precisa do secret `CLIENT_RELEASE_TOKEN` (fine-grained PAT com Contents: Read and write só naquele repositório). A release inclui também o manifesto assinado `RELEASE` (+ `RELEASE.sig`), gerado com a variável `CLIENT_SIGNING_PUBKEY` e o secret `CLIENT_SIGNING_KEY`; veja a seção *Atualizações* do README principal.

O `install.sh` publicado é gerado de `packaging/install.sh` com a chave pública embutida (`python -m crptochat.update installer packaging/install.sh`, que lê `CLIENT_SIGNING_PUBKEY`). Ele confere `RELEASE.sig` e o SHA-256 do binário contra o manifesto assinado e recusa qualquer divergência. O arquivo do repositório, sem a chave, se recusa a rodar. Sem `CLIENT_SIGNING_PUBKEY` o instalador não é publicado.

PyInstaller empacota bytecode Python, não o `.py` original. Isso esconde o código no uso comum, mas não é proteção forte: o bytecode ainda pode ser extraído e descompilado.
