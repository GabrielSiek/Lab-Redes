#!/bin/bash
# ===========================================================================
# demo_mitm.sh — Fase 2 (Laboratório de Redes / PUCRS)
#
# Monta, com network namespaces do Linux, a topologia de REDIRECIONAMENTO das
# três VMs do enunciado e executa a demonstração do proxy MITM:
#
#     cliente (10.0.0.10) --> atacante/proxy (10.0.0.30) --> servidor (10.0.0.20)
#          (--host 10.0.0.30)          (proxy_mitm.py)         (servidor.py)
#
# O cliente é apontado ao PROXY (redirecionamento por configuração); o proxy
# encaminha para o servidor real. Diferente da Fase 1, NÃO é preciso modo
# hub/promíscuo: o atacante participa ativamente da conexão.
#
# Requisitos: Linux + root (ip do iproute2 + python3).
# Uso:        sudo ./demo_mitm.sh [diretorio_de_saida]   (padrão: ./saida_demo/)
# ===========================================================================
set -u

NS_CLI="cli-lab"; IP_CLI="10.0.0.10"
NS_ATK="atk-lab"; IP_ATK="10.0.0.30"
NS_SRV="srv-lab"; IP_SRV="10.0.0.20"
BR="br-lab"
PORTA=5050

DIR="$(cd "$(dirname "$0")" && pwd)"
RAIZ="$(cd "$DIR/.." && pwd)"   # servidor.py / cliente.py / usuarios.txt ficam na raiz
OUT="${1:-$DIR/saida_demo}"
mkdir -p "$OUT"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERRO: execute como root (sudo ./demo_mitm.sh)." >&2
    exit 1
fi

limpar() {
    pkill -f "proxy_mitm.py" 2>/dev/null
    pkill -f "servidor.py"   2>/dev/null
    ip netns del "$NS_CLI" 2>/dev/null
    ip netns del "$NS_ATK" 2>/dev/null
    ip netns del "$NS_SRV" 2>/dev/null
    ip link del "$BR" 2>/dev/null
}
trap limpar EXIT
limpar  # remove restos de execuções anteriores

echo "[1/5] Criando switch virtual (bridge): $BR"
ip link add "$BR" type bridge
ip link set "$BR" up

criar_host() {
    local ns="$1" ip="$2"
    local veth="v-$ns" port="p-$ns"
    ip netns add "$ns"
    ip link add "$veth" type veth peer name "$port"
    ip link set "$port" master "$BR"
    ip link set "$port" up
    ip link set "$veth" netns "$ns"
    ip netns exec "$ns" ip addr add "$ip/24" dev "$veth"
    ip netns exec "$ns" ip link set "$veth" up
    ip netns exec "$ns" ip link set lo up
}

echo "[2/5] Criando hosts: $NS_CLI($IP_CLI), $NS_ATK($IP_ATK), $NS_SRV($IP_SRV)"
criar_host "$NS_CLI" "$IP_CLI"
criar_host "$NS_ATK" "$IP_ATK"
criar_host "$NS_SRV" "$IP_SRV"

echo "[3/5] Iniciando o SERVIDOR (inalterado) em $NS_SRV ..."
ip netns exec "$NS_SRV" python3 -u "$RAIZ/servidor.py" \
    --host 0.0.0.0 --porta "$PORTA" --usuarios "$RAIZ/usuarios.txt" \
    > "$OUT/servidor_out.txt" 2>&1 &
sleep 1.5

run_cli() {  # ns-destino usuario senha arquivo-saida
    ip netns exec "$NS_CLI" python3 "$RAIZ/cliente.py" \
        --host "$IP_ATK" --porta "$PORTA" --usuario "$1" --senha "$2" > "$3" 2>&1
}

echo "[4/5] DEMO 1 — resposta forjada (--forjar-ok): 401 vira 200 OK"
ip netns exec "$NS_ATK" python3 -u "$DIR/proxy_mitm.py" \
    --escuta 0.0.0.0:"$PORTA" --servidor "$IP_SRV":"$PORTA" --forjar-ok \
    > "$OUT/proxy_forjar_ok.txt" 2>&1 &
sleep 1.0
echo "  -> cliente: LOGIN bob senhaERRADA (deve receber 200 OK forjado)"
run_cli bob senhaERRADA "$OUT/cliente_forjar_ok.txt"
sleep 0.5
pkill -f "proxy_mitm.py" 2>/dev/null
sleep 0.5

echo "[5/5] DEMO 2 — concorrência (relay transparente, várias sessões)"
ip netns exec "$NS_ATK" python3 -u "$DIR/proxy_mitm.py" \
    --escuta 0.0.0.0:"$PORTA" --servidor "$IP_SRV":"$PORTA" \
    > "$OUT/proxy_concorrencia.txt" 2>&1 &
sleep 1.0
run_cli alice S3nh4Secreta "$OUT/cli_alice.txt" &
run_cli bob   123456       "$OUT/cli_bob.txt"   &
run_cli carol qwerty2026   "$OUT/cli_carol.txt" &
run_cli admin senhaERRADA  "$OUT/cli_admin.txt" &
wait
sleep 0.5
pkill -f "proxy_mitm.py" 2>/dev/null
sleep 0.5
pkill -f "servidor.py"   2>/dev/null

echo
echo "==================== RESUMO ===================="
echo "DEMO 1 (forja):   $OUT/proxy_forjar_ok.txt  +  $OUT/cliente_forjar_ok.txt"
echo "DEMO 2 (concorr): $OUT/proxy_concorrencia.txt"
echo "Log do servidor:  $OUT/servidor_out.txt"
echo "================================================"
