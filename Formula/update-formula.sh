#!/usr/bin/env bash
#
# Atualiza a fórmula do Homebrew para um lançamento novo.
#
# O QUE ISTO FAZ, EM LINGUAGEM SIMPLES
# ------------------------------------
# Uma fórmula do Homebrew precisa da "impressão digital" (SHA-256) do pacote da
# versão publicada. Se ela não bater, o Homebrew recusa a instalação — é a
# proteção dele contra um pacote adulterado.
#
# Este script baixa o pacote da versão que você indicar, calcula a impressão
# digital e a escreve na fórmula. Rode-o SEMPRE depois de publicar uma versão.
#
# USO
#     ./Formula/update-formula.sh v1.0.0

set -euo pipefail

REPO="1985epma/epma-windows-usb-creator"
FORMULA="$(dirname "$0")/epma-windows-usb-creator.rb"

if [ $# -ne 1 ]; then
    echo "Uso: $0 <versao>"
    echo "Exemplo: $0 v1.0.0"
    exit 1
fi

VERSAO="$1"
URL="https://github.com/${REPO}/archive/refs/tags/${VERSAO}.tar.gz"

echo "Versão:  $VERSAO"
echo "Pacote:  $URL"
echo

echo "Conferindo se a versão existe..."
if ! curl -sfIL "$URL" >/dev/null 2>&1; then
    echo "ERRO: não foi possível baixar o pacote dessa versão."
    echo
    echo "A tag '$VERSAO' provavelmente ainda não existe no GitHub. Publique-a com:"
    echo "    git tag $VERSAO && git push origin $VERSAO"
    exit 1
fi

echo "Baixando e calculando a impressão digital..."
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl -sfL "$URL" -o "$TMP/pacote.tar.gz"

if command -v shasum >/dev/null 2>&1; then
    SHA="$(shasum -a 256 "$TMP/pacote.tar.gz" | awk '{print $1}')"
else
    SHA="$(sha256sum "$TMP/pacote.tar.gz" | awk '{print $1}')"
fi

echo "SHA-256: $SHA"
echo

# Atualiza url e sha256 na fórmula, preservando o resto do arquivo.
python3 - "$FORMULA" "$URL" "$SHA" <<'PY'
import re, sys
caminho, url, sha = sys.argv[1], sys.argv[2], sys.argv[3]
with open(caminho, encoding="utf-8") as fh:
    texto = fh.read()
texto, n_url = re.subn(r'^(  url\s+)"[^"]*"', rf'\g<1>"{url}"', texto, count=1, flags=re.M)
texto, n_sha = re.subn(r'^(  sha256\s+)"[^"]*"', rf'\g<1>"{sha}"', texto, count=1, flags=re.M)
if not (n_url and n_sha):
    sys.exit("ERRO: não foi possível localizar as linhas 'url' e 'sha256' na fórmula.")
with open(caminho, "w", encoding="utf-8") as fh:
    fh.write(texto)
print(f"Fórmula atualizada: {caminho}")
PY

echo
echo "Pronto. Confira a alteração com:  git diff $FORMULA"
echo "Depois teste com:                 brew install --formula $FORMULA"
