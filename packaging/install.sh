#!/bin/sh
# Instala (ou atualiza) o cliente crptochat a partir da release publicada no
# site https://crptochat.acpt.app.br/downloads/ (sem login nem token).
#
#   sh install.sh                     # instala em ~/.local/bin/crptochat
#   CRPTOCHAT_BIN_DIR=/usr/local/bin sudo -E sh install.sh
#   CRPTOCHAT_UPDATE_URL=https://espelho/ sh install.sh   # outra origem (só https)
#
# Segurança: a chave pública de assinatura vai embutida neste arquivo quando a
# release é publicada. Antes de instalar, o script confere a assinatura
# Ed25519 do manifesto RELEASE (RELEASE.sig) com essa chave e depois o SHA-256
# do binário contra o manifesto assinado. Qualquer divergência, assinatura
# ausente ou impossibilidade de conferir cancela a instalação.
#
# Sem downgrade: recusa uma release com build mais antigo que o do binário já
# instalado (ou do último instalado por este script), mesmo assinada, para que
# uma release velha e vulnerável não possa ser reaproveitada. Para voltar de
# propósito a uma versão anterior:
#   sh install.sh --allow-downgrade      (ou CRPTOCHAT_ALLOW_DOWNGRADE=1)
#
# Para testar com uma cópia local da release: CRPTOCHAT_RELEASE_DIR=/pasta
# (a assinatura continua obrigatória).
set -eu

ALLOW_DOWNGRADE="${CRPTOCHAT_ALLOW_DOWNGRADE:-0}"
for arg in "$@"; do
    case "$arg" in
        --allow-downgrade) ALLOW_DOWNGRADE=1 ;;
        *) echo "opção desconhecida: $arg (só existe --allow-downgrade)" >&2; exit 2 ;;
    esac
done

BASE="${CRPTOCHAT_UPDATE_URL:-https://crptochat.acpt.app.br/downloads/}"
DEST="${CRPTOCHAT_BIN_DIR:-$HOME/.local/bin}"
# Chave pública Ed25519 (base64, 32 bytes), gravada aqui pela publicação.
PUBKEY="@CRPTOCHAT_SIGNING_PUBKEY@"
# SHA-256 dessa chave, como publicada no README (gravada junto com a chave).
FINGERPRINT="@CRPTOCHAT_SIGNING_FINGERPRINT@"

fail() {
    echo "instalação cancelada: $*" >&2
    exit 1
}

case "$PUBKEY" in
    @*@|"") fail "este install.sh não tem a chave de assinatura embutida; baixe o da release" ;;
esac
printf '%s' "$PUBKEY" | grep -Eq '^[A-Za-z0-9+/]{43}=$' || fail "chave de assinatura embutida inválida"
printf '%s' "$FINGERPRINT" | grep -Eq '^([0-9a-f]{4} ){15}[0-9a-f]{4}$' || fail "fingerprint embutida inválida"

# Quando dá para calcular aqui (base64 + sha256sum/shasum/openssl), confere que a
# fingerprint embutida é mesmo a da chave embutida.
b64decode() {
    if base64 -d </dev/null >/dev/null 2>&1; then base64 -d
    elif base64 -D </dev/null >/dev/null 2>&1; then base64 -D
    elif command -v openssl >/dev/null 2>&1; then openssl base64 -d -A
    else return 1
    fi
}
sha256hex() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then shasum -a 256 | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 -r | awk '{print $1}'
    else return 1
    fi
}
# (no pipeline o código de saída é o do último comando: confere o decodificador antes)
derived=""
if printf 'QQ==' | b64decode >/dev/null 2>&1 && printf '' | sha256hex >/dev/null 2>&1; then
    derived="$(printf '%s' "$PUBKEY" | b64decode 2>/dev/null | sha256hex 2>/dev/null)" || derived=""
fi
if printf '%s' "$derived" | grep -Eq '^[0-9a-f]{64}$'; then
    [ "$(printf '%s' "$derived" | sed 's/..../& /g; s/ $//')" = "$FINGERPRINT" ] \
        || fail "a fingerprint embutida não é a da chave embutida (instalador adulterado?)"
fi

case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=macos ;;
    *) fail "sistema não suportado: $(uname -s)" ;;
esac
case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) fail "arquitetura não suportada: $(uname -m)" ;;
esac
asset="crptochat-$os-$arch"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

fetch() {
    if [ -n "${CRPTOCHAT_RELEASE_DIR:-}" ]; then
        for name in "$asset" RELEASE RELEASE.sig; do
            [ -f "$CRPTOCHAT_RELEASE_DIR/$name" ] && cp "$CRPTOCHAT_RELEASE_DIR/$name" "$tmp/$name"
        done
        return 0
    fi
    case "$BASE" in
        https://*) ;;
        *) fail "origem de download precisa ser https:// (recebi: $BASE)" ;;
    esac
    case "$BASE" in */) ;; *) BASE="$BASE/" ;; esac
    command -v curl >/dev/null 2>&1 || return 1
    for name in "$asset" RELEASE RELEASE.sig; do
        # só https, inclusive nos redirecionamentos; limite de tamanho e de tempo
        curl -fsSL --proto '=https' --proto-redir '=https' --max-filesize 209715200 --max-time 600 \
            -o "$tmp/$name" "$BASE$name" || return 1
    done
}

if ! fetch; then
    echo "não foi possível baixar $asset de $BASE (precisa do curl e de acesso ao site)." >&2
    exit 1
fi
[ -f "$tmp/$asset" ] || fail "a release não tem $asset"
[ -f "$tmp/RELEASE" ] || fail "a release não tem o manifesto RELEASE"
[ -s "$tmp/RELEASE.sig" ] || fail "a release não está assinada (falta RELEASE.sig)"

# 1. Assinatura do manifesto. OpenSSL 3 sabe conferir Ed25519; sem ele, tenta
#    o Python com a biblioteca cryptography. Sem nenhum dos dois, não instala.
# o openssl do PATH, ou o OpenSSL 3 do Homebrew (que não entra no PATH no macOS)
find_openssl3() {
    for candidate in "$(command -v openssl 2>/dev/null || true)" /opt/homebrew/opt/openssl@3/bin/openssl \
            /usr/local/opt/openssl@3/bin/openssl; do
        [ -n "$candidate" ] && [ -x "$candidate" ] || continue
        if "$candidate" version 2>/dev/null | grep -q '^OpenSSL [3-9]'; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

verify_openssl() {
    ossl="$(find_openssl3)" || return 2
    {
        echo "-----BEGIN PUBLIC KEY-----"
        # prefixo DER SubjectPublicKeyInfo de Ed25519 (12 bytes) + chave em base64
        echo "MCowBQYDK2VwAyEA$PUBKEY"
        echo "-----END PUBLIC KEY-----"
    } > "$tmp/pub.pem"
    tr -d '\r\n ' < "$tmp/RELEASE.sig" > "$tmp/sig.b64"
    "$ossl" base64 -d -A -in "$tmp/sig.b64" -out "$tmp/sig.bin" 2>/dev/null || return 1
    [ "$(wc -c < "$tmp/sig.bin" | tr -d ' ')" = 64 ] || return 1
    "$ossl" pkeyutl -verify -pubin -inkey "$tmp/pub.pem" -rawin -in "$tmp/RELEASE" \
        -sigfile "$tmp/sig.bin" >/dev/null 2>&1
}

verify_python() {
    for py in python3 python; do
        command -v "$py" >/dev/null 2>&1 || continue
        "$py" -I -c 'import cryptography' 2>/dev/null || continue
        "$py" -I - "$PUBKEY" "$tmp/RELEASE" "$tmp/RELEASE.sig" <<'PY'
import base64, sys
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
key, manifest, sig = sys.argv[1], open(sys.argv[2], "rb").read(), open(sys.argv[3], "rb").read()
try:
    Ed25519PublicKey.from_public_bytes(base64.b64decode(key, validate=True)).verify(
        base64.b64decode(b"".join(sig.split()), validate=True), manifest)
except (InvalidSignature, ValueError):
    sys.exit(1)
PY
        return $?
    done
    return 2
}

status=0
verify_openssl || status=$?
if [ "$status" -eq 2 ]; then
    status=0
    verify_python || status=$?
fi
case "$status" in
    0) ;;
    2) fail "não há como conferir a assinatura aqui: instale o OpenSSL 3 (ou python3 com cryptography)" ;;
    *) fail "ASSINATURA INVÁLIDA: o manifesto RELEASE não foi assinado pela chave deste instalador" ;;
esac

# 2. O manifesto assinado é deste formato e lista o binário desta plataforma.
[ "$(head -n 1 "$tmp/RELEASE")" = "crptochat-release 1" ] || fail "manifesto RELEASE em formato desconhecido"
expected="$(awk -v name="$asset" 'NF == 2 && $2 == name { print $1 }' "$tmp/RELEASE")"
printf '%s' "$expected" | grep -Eq '^[0-9a-f]{64}$' || fail "o manifesto assinado não lista $asset"
version="$(sed -n 's/^version //p' "$tmp/RELEASE")"
built="$(sed -n 's/^built //p' "$tmp/RELEASE")"
printf '%s' "$built" | grep -Eq '^[0-9]{1,12}$' || fail "manifesto assinado sem data de build válida"

# 3. SHA-256 do binário baixado contra o manifesto assinado.
if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$tmp/$asset" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')"
elif command -v openssl >/dev/null 2>&1; then
    actual="$(openssl dgst -sha256 -r "$tmp/$asset" | awk '{print $1}')"
else
    fail "não há como calcular SHA-256 (sha256sum, shasum ou openssl)"
fi
[ "$actual" = "$expected" ] || fail "SHA-256 de $asset não confere com o manifesto assinado"
echo "assinatura e SHA-256 conferidos: $asset $version"
# a mesma fingerprint está publicada no README do repositório do crptochat:
# confira por lá que este instalador traz a chave certa
echo "chave de assinatura deste instalador: SHA256 $FINGERPRINT"

# 4. Sem downgrade. A data do build está dentro do manifesto assinado; o piso é
#    o maior entre o build do binário instalado (crptochat --build-info, 1.8+)
#    e o último que este script instalou.
state="${XDG_STATE_HOME:-$HOME/.local/state}/crptochat"
receipt="$state/installed-build"
floor=0
if [ -x "$DEST/crptochat" ]; then
    have="$("$DEST/crptochat" --build-info 2>/dev/null | awk '$1 == "crptochat-build" { print $4; exit }')" || have=""
    printf '%s' "$have" | grep -Eq '^[0-9]{1,12}$' && floor="$have"
fi
if [ -f "$receipt" ]; then
    last="$(head -n 1 "$receipt")"
    if printf '%s' "$last" | grep -Eq '^[0-9]{1,12}$' && [ "$last" -gt "$floor" ]; then
        floor="$last"
    fi
fi
if [ "$built" -lt "$floor" ]; then
    if [ "$ALLOW_DOWNGRADE" = 1 ]; then
        echo "aviso: instalando um build MAIS ANTIGO que o atual, como pedido (--allow-downgrade)" >&2
    else
        fail "a release ($version, build $built) é mais antiga que o instalado (build $floor); \
use --allow-downgrade se for de propósito"
    fi
fi

mkdir -p "$DEST"
install -m 0755 "$tmp/$asset" "$DEST/crptochat"
mkdir -p "$state" && printf '%s\n' "$built" > "$receipt"
echo "instalado: $DEST/crptochat ($("$DEST/crptochat" --version 2>/dev/null || echo "versão $version"))"
case ":$PATH:" in
    *":$DEST:"*) ;;
    *) echo "adicione $DEST ao PATH para usar o comando 'crptochat'" ;;
esac
command -v ffmpeg >/dev/null 2>&1 || echo "dica: instale o ffmpeg para enviar mensagens de voz mascaradas"
