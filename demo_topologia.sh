#!/bin/bash
# ===========================================================================
# demo_topologia.sh — Fase 1 (Laboratório de Redes / PUCRS)
#
# Monta, com network namespaces do Linux, uma topologia equivalente às três
# VMs do enunciado (VM-cliente, VM-servidor, VM-observador) num segmento de
# rede ISOLADO, e executa a demonstração completa automaticamente:
#
#     cliente (10.0.0.10) ---+
#                            +--- [ switch virtual br-lab ] --- observador (10.0.0.30)
#     servidor (10.0.0.20) --+           (modo hub)              (sniffer passivo)
#
# O "switch" é uma bridge configurada como HUB (sem aprendizado de MAC, com
# flooding), de modo que o observador enxerga TODO o tráfego do segmento —
# como uma VM-observador em modo promíscuo. Por serem hosts separados numa
# rede real, NÃO há a duplicação de pacotes que ocorre em loopback (lo).
#
# Requisitos: Linux + root (ip/bridge do iproute2 + python3).
# Uso:        sudo ./demo_topologia.sh [diretorio_de_saida]
#             (saída padrão: ./saida_demo/)
# ===========================================================================
set -u

NS_CLI="cli-lab"; IP_CLI="10.0.0.10"
NS_SRV="srv-lab"; IP_SRV="10.0.0.20"
NS_OBS="obs-lab"; IP_OBS="10.0.0.30"
BR="br-lab"
PORTA=5050

DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$DIR/saida_demo}"
mkdir -p "$OUT"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERRO: execute como root (sudo ./demo_topologia.sh)." >&2
    exit 1
fi

limpar() {
    ip netns del "$NS_CLI" 2>/dev/null
    ip netns del "$NS_SRV" 2>/dev/null
    ip netns del "$NS_OBS" 2>/dev/null
    ip link del "$BR" 2>/dev/null
}
trap limpar EXIT
limpar  # remove restos de execuções anteriores

echo "[1/5] Criando switch virtual (bridge em modo hub): $BR"
ip link add "$BR" type bridge
ip link set "$BR" up

criar_host() {
    local ns="$1" ip="$2"
    local veth="v-$ns" port="p-$ns"
    ip netns add "$ns"
    ip link add "$veth" type veth peer name "$port"
    ip link set "$port" master "$BR"
    ip link set "$port" up
    # transforma a bridge em HUB nesta porta: inunda e não aprende MAC,
    # garantindo que o observador receba todo o tráfego do segmento.
    bridge link set dev "$port" learning off flood on 2>/dev/null
    ip link set "$veth" netns "$ns"
    ip netns exec "$ns" ip addr add "$ip/24" dev "$veth"
    ip netns exec "$ns" ip link set "$veth" up
    ip netns exec "$ns" ip link set lo up
}

echo "[2/5] Criando hosts: $NS_CLI($IP_CLI), $NS_SRV($IP_SRV), $NS_OBS($IP_OBS)"
criar_host "$NS_CLI" "$IP_CLI"
criar_host "$NS_SRV" "$IP_SRV"
criar_host "$NS_OBS" "$IP_OBS"
# observador em modo promíscuo (aceita quadros não destinados a ele)
ip netns exec "$NS_OBS" ip link set "v-$NS_OBS" promisc on

echo "[3/5] Iniciando o SERVIDOR em $NS_SRV ..."
ip netns exec "$NS_SRV" python3 -u "$DIR/servidor.py" \
    --host 0.0.0.0 --porta "$PORTA" --usuarios "$DIR/usuarios.txt" \
    > "$OUT/servidor_out.txt" 2>&1 &
sleep 1.5

echo "[4/5] Iniciando o SNIFFER (passivo) em $NS_OBS ..."
ip netns exec "$NS_OBS" python3 -u "$DIR/sniffer.py" \
    --interface "v-$NS_OBS" --porta "$PORTA" --pcap "$OUT/captura.pcap" \
    > "$OUT/sniffer_out.txt" 2>&1 &
sleep 1.5

echo "[5/5] Rodando sessões do CLIENTE em $NS_CLI ..."
run_cli() {  # usuario senha
    ip netns exec "$NS_CLI" python3 "$DIR/cliente.py" \
        --host "$IP_SRV" --porta "$PORTA" --usuario "$1" --senha "$2"
}
echo "  -> alice (credenciais válidas)";  run_cli alice S3nh4Secreta; sleep 0.3
echo "  -> bob (senha errada)";           run_cli bob   senhaERRADA;  sleep 0.3
echo "  -> admin (credenciais válidas)";  run_cli admin admin;        sleep 0.3
echo "  -> carol (credenciais válidas)";  run_cli carol qwerty2026;   sleep 0.3

# Demonstração de concorrência: dois clientes simultâneos (atendidos em paralelo
# pelo servidor, que trata cada conexão em uma thread).
echo "  -> concorrência: alice + carol em paralelo"
run_cli alice S3nh4Secreta > /dev/null 2>&1 &
P1=$!
run_cli carol qwerty2026   > /dev/null 2>&1 &
P2=$!
wait "$P1" "$P2"   # aguarda SÓ os clientes (não o servidor/sniffer de fundo)

sleep 1
# encerra sniffer (SIGINT -> fecha o pcap e imprime o resumo) e servidor
pkill -INT -f "sniffer.py"  2>/dev/null
sleep 1.5
pkill -f "servidor.py"      2>/dev/null
sleep 0.3

echo
echo "==================== RESUMO ===================="
echo "Saída do sniffer : $OUT/sniffer_out.txt"
echo "Log do servidor  : $OUT/servidor_out.txt"
echo "Captura (pcap)   : $OUT/captura.pcap"
echo "Abra o pcap com  : wireshark '$OUT/captura.pcap'   (ou: tshark -r ...)"
echo "================================================"
