#!/usr/bin/env bash
# ===========================================================================
# gerar_certificados.sh — Fase 3 (Laboratório de Redes / PUCRS)
#
# Gera a infraestrutura de chaves usada pela defesa TLS:
#
#   1. Uma Autoridade Certificadora (CA) própria do laboratório.
#   2. O certificado do SERVIDOR, assinado por essa CA (identidade legítima).
#   3. Um certificado de ATACANTE, auto-assinado (NÃO assinado pela CA), usado
#      apenas para demonstrar que um MITM que tenta se passar pelo servidor é
#      detectado pelo cliente (erro de validação de certificado).
#
# O cliente confia APENAS na CA (ca.crt). Por isso:
#   - o certificado do servidor valida (foi assinado pela CA);
#   - o certificado do atacante NÃO valida (a CA não o assinou) -> ataque
#     detectado no handshake.
#
# O nome lógico do servidor é "servidor-auth" (vai no campo SAN do certificado
# e é verificado pelo cliente), tornando a autenticação independente do IP.
#
# Uso: ./gerar_certificados.sh        (idempotente; regrava em ./certs/)
# Requisito: openssl (3.x). Funciona em Linux e no Git Bash do Windows.
# ===========================================================================
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
CERTS="$DIR/certs"
NOME_SERVIDOR="servidor-auth"
DIAS=825

mkdir -p "$CERTS"
cd "$CERTS"

echo "[1/4] Autoridade Certificadora (CA) do laboratório..."
openssl req -x509 -newkey rsa:2048 -sha256 -days "$DIAS" -nodes \
    -keyout ca.key -out ca.crt \
    -subj "/C=BR/ST=RS/O=Lab Redes PUCRS/CN=Lab-Redes-CA" >/dev/null 2>&1

echo "[2/4] Chave e CSR do servidor (CN=$NOME_SERVIDOR)..."
openssl req -newkey rsa:2048 -sha256 -nodes \
    -keyout servidor.key -out servidor.csr \
    -subj "/C=BR/ST=RS/O=Lab Redes PUCRS/CN=$NOME_SERVIDOR" >/dev/null 2>&1

# SAN: nome lógico + nomes/endereços usados no laboratório (namespaces e loopback)
cat > servidor_ext.cnf <<EOF
subjectAltName = DNS:$NOME_SERVIDOR, DNS:localhost, IP:10.0.0.20, IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF

echo "[3/4] Certificado do servidor assinado pela CA..."
openssl x509 -req -in servidor.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days "$DIAS" -sha256 -extfile servidor_ext.cnf -out servidor.crt >/dev/null 2>&1

echo "[4/4] Certificado de ATACANTE (auto-assinado, NÃO confiável)..."
# Mesmo CN do servidor, mas assinado por si mesmo -> a CA do cliente não o
# reconhece. Serve só para a demonstração de DETECÇÃO do MITM.
openssl req -x509 -newkey rsa:2048 -sha256 -days "$DIAS" -nodes \
    -keyout atacante.key -out atacante.crt \
    -addext "subjectAltName = DNS:$NOME_SERVIDOR, IP:10.0.0.30, IP:127.0.0.1" \
    -subj "/C=BR/ST=RS/O=Atacante/CN=$NOME_SERVIDOR" >/dev/null 2>&1

rm -f servidor.csr servidor_ext.cnf ca.srl
chmod 600 ./*.key 2>/dev/null || true

echo
echo "=== Certificados gerados em: $CERTS ==="
echo "  ca.crt        CA do laboratório (o CLIENTE confia nela)"
echo "  servidor.crt  identidade legítima do servidor (assinada pela CA)"
echo "  servidor.key  chave privada do servidor"
echo "  atacante.crt  identidade FALSA (auto-assinada) para a demo de detecção"
echo "  atacante.key  chave privada do atacante"
echo
echo "Verificação (deve dizer 'servidor.crt: OK'):"
openssl verify -CAfile ca.crt servidor.crt || true
echo "Verificação do atacante contra a CA (deve FALHAR):"
openssl verify -CAfile ca.crt atacante.crt || true
