#!/usr/bin/env bash
# ===========================================================================
# demo_defesa.sh — Fase 3 (Laboratório de Redes / PUCRS)
#
# Monta a MESMA topologia das fases anteriores com network namespaces do Linux
# (cliente 10.0.0.10, atacante 10.0.0.30, servidor 10.0.0.20 numa bridge) e
# executa a bateria de evidências da defesa, capturando o tráfego com tcpdump:
#
#   ANTES    (Fase 1):  servidor/cliente em TEXTO CLARO  -> captura antes.pcap
#   DEPOIS   (Fase 3):  servidor/cliente com TLS          -> captura depois.pcap
#   SNIFFER:            sniffer.py da Fase 1 contra o TLS  -> sniffer_tls.txt
#   MITM:               mitm_tls_intercept contra o cliente-> captura mitm.pcap
#
# Requisitos: Linux + root (ip do iproute2, python3, tcpdump).
# Uso:        sudo ./demo_defesa.sh [diretorio_de_saida]  (padrão: ./saida_demo)
# ===========================================================================
set -u

NS_CLI="cli-lab"; IP_CLI="10.0.0.10"
NS_ATK="atk-lab"; IP_ATK="10.0.0.30"
NS_SRV="srv-lab"; IP_SRV="10.0.0.20"
BR="br-lab"; PORTA=5050

DIR="$(cd "$(dirname "$0")" && pwd)"
RAIZ="$(cd "$DIR/.." && pwd)"          # servidor.py / cliente.py / usuarios.txt
OUT="${1:-$DIR/saida_demo}"
CERTS="$DIR/certs"
mkdir -p "$OUT"

[ "$(id -u)" -eq 0 ] || { echo "ERRO: rode como root (sudo)." >&2; exit 1; }
command -v tcpdump >/dev/null || { echo "ERRO: tcpdump nao instalado." >&2; exit 1; }

# Certificados e hashes (gera se faltarem)
[ -f "$CERTS/servidor.crt" ] || bash "$DIR/gerar_certificados.sh"
[ -f "$DIR/usuarios_hash.txt" ] || python3 "$DIR/gerar_hashes.py"

limpar() {
    pkill -f "servidor.py"   2>/dev/null
    pkill -f "servidor_tls.py" 2>/dev/null
    pkill -f "mitm_tls_intercept.py" 2>/dev/null
    pkill -f "sniffer.py"    2>/dev/null
    pkill tcpdump 2>/dev/null
    ip netns del "$NS_CLI" 2>/dev/null
    ip netns del "$NS_ATK" 2>/dev/null
    ip netns del "$NS_SRV" 2>/dev/null
    ip link del "$BR" 2>/dev/null
}
trap limpar EXIT
limpar

echo "[infra] bridge $BR + 3 namespaces (cli/atk/srv)"
ip link add "$BR" type bridge; ip link set "$BR" up
criar_host() {
    local ns="$1" ip="$2" veth="v-$1" port="p-$1"
    ip netns add "$ns"
    ip link add "$veth" type veth peer name "$port"
    ip link set "$port" master "$BR"; ip link set "$port" up
    ip link set "$veth" netns "$ns"
    ip netns exec "$ns" ip addr add "$ip/24" dev "$veth"
    ip netns exec "$ns" ip link set "$veth" up
    ip netns exec "$ns" ip link set lo up
}
criar_host "$NS_CLI" "$IP_CLI"
criar_host "$NS_ATK" "$IP_ATK"
criar_host "$NS_SRV" "$IP_SRV"

cap_inicia() { tcpdump -i "$BR" -w "$OUT/$1" "tcp port $PORTA" >/dev/null 2>&1 & echo $!; sleep 1; }
cap_para()   { kill -INT "$1" 2>/dev/null; sleep 1; }

# --------------------------------------------------------------------------
echo
echo "========== ANTES (Fase 1): login em TEXTO CLARO =========="
CAP=$(cap_inicia antes.pcap)
ip netns exec "$NS_SRV" python3 -u "$RAIZ/servidor.py" \
    --host 0.0.0.0 --porta "$PORTA" --usuarios "$RAIZ/usuarios.txt" \
    > "$OUT/antes_servidor.txt" 2>&1 &
sleep 1.5
ip netns exec "$NS_CLI" python3 "$RAIZ/cliente.py" \
    --host "$IP_SRV" --porta "$PORTA" --usuario alice --senha S3nh4Secreta \
    > "$OUT/antes_cliente.txt" 2>&1
sleep 0.5; pkill -f "servidor.py" 2>/dev/null; cap_para "$CAP"
echo "  -> $OUT/antes.pcap (a senha trafega legivel)"

# --------------------------------------------------------------------------
echo
echo "========== DEPOIS (Fase 3): login com TLS =========="
CAP=$(cap_inicia depois.pcap)
ip netns exec "$NS_SRV" python3 -u "$DIR/servidor_tls.py" \
    --host 0.0.0.0 --porta "$PORTA" \
    --cert "$CERTS/servidor.crt" --chave "$CERTS/servidor.key" \
    --usuarios "$DIR/usuarios_hash.txt" \
    > "$OUT/depois_servidor.txt" 2>&1 &
sleep 1.5
ip netns exec "$NS_CLI" python3 "$DIR/cliente_tls.py" \
    --host "$IP_SRV" --porta "$PORTA" --cafile "$CERTS/ca.crt" \
    --usuario alice --senha S3nh4Secreta \
    > "$OUT/depois_cliente.txt" 2>&1
sleep 0.5
# segunda sessao para gerar mais trafego cifrado na captura
ip netns exec "$NS_CLI" python3 "$DIR/cliente_tls.py" \
    --host "$IP_SRV" --porta "$PORTA" --cafile "$CERTS/ca.crt" \
    --usuario bob --senha 123456 >> "$OUT/depois_cliente.txt" 2>&1
sleep 0.5; pkill -f "servidor_tls.py" 2>/dev/null; cap_para "$CAP"
echo "  -> $OUT/depois.pcap (tudo cifrado: Application Data)"

# --------------------------------------------------------------------------
echo
echo "========== SNIFFER da Fase 1 contra o TLS =========="
ip netns exec "$NS_SRV" python3 -u "$DIR/servidor_tls.py" \
    --host 0.0.0.0 --porta "$PORTA" \
    --cert "$CERTS/servidor.crt" --chave "$CERTS/servidor.key" \
    --usuarios "$DIR/usuarios_hash.txt" > /dev/null 2>&1 &
sleep 1.5
# sniffer escuta na interface do atacante, em modo promiscuo
ip netns exec "$NS_ATK" python3 -u "$RAIZ/sniffer.py" \
    --interface "v-$NS_ATK" --porta "$PORTA" \
    > "$OUT/sniffer_tls.txt" 2>&1 &
SNIFFPID=$!
sleep 1
ip netns exec "$NS_CLI" python3 "$DIR/cliente_tls.py" \
    --host "$IP_SRV" --porta "$PORTA" --cafile "$CERTS/ca.crt" \
    --usuario alice --senha S3nh4Secreta > /dev/null 2>&1
sleep 1; kill -INT "$SNIFFPID" 2>/dev/null; sleep 1
pkill -f "servidor_tls.py" 2>/dev/null
echo "  -> $OUT/sniffer_tls.txt (nenhuma credencial em texto claro)"

# --------------------------------------------------------------------------
echo
echo "========== MITM-TLS: cliente DETECTA o atacante =========="
CAP=$(cap_inicia mitm.pcap)
ip netns exec "$NS_ATK" python3 -u "$DIR/mitm_tls_intercept.py" \
    --escuta 0.0.0.0:"$PORTA" --servidor "$IP_SRV":"$PORTA" \
    --cert "$CERTS/atacante.crt" --chave "$CERTS/atacante.key" \
    > "$OUT/mitm_atacante.txt" 2>&1 &
sleep 1.5
# cliente aponta para o ATACANTE (10.0.0.30), mas valida o nome do servidor
ip netns exec "$NS_CLI" python3 "$DIR/cliente_tls.py" \
    --host "$IP_ATK" --porta "$PORTA" --cafile "$CERTS/ca.crt" \
    --usuario alice --senha S3nh4Secreta \
    > "$OUT/mitm_cliente.txt" 2>&1
echo "  (exit do cliente: $? — 3 = ataque detectado)"
sleep 0.5; pkill -f "mitm_tls_intercept.py" 2>/dev/null; cap_para "$CAP"
echo "  -> $OUT/mitm.pcap + mitm_cliente.txt + mitm_atacante.txt"

echo
echo "==================== RESUMO ===================="
echo "ANTES  : $OUT/antes.pcap    + antes_cliente.txt"
echo "DEPOIS : $OUT/depois.pcap   + depois_cliente.txt"
echo "SNIFFER: $OUT/sniffer_tls.txt"
echo "MITM   : $OUT/mitm.pcap     + mitm_cliente.txt / mitm_atacante.txt"
echo "================================================"
