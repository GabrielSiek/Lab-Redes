#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interceptador passivo (sniffer de aplicação) — Fase 1 (Lab. de Redes / PUCRS).

Ferramenta de ESCUTA PASSIVA que demonstra a quebra de CONFIDENCIALIDADE do
serviço-alvo: como o protocolo trafega em texto claro, um observador no mesmo
segmento de rede consegue ler as credenciais sem participar da conexão.

Captura com SOCKET RAW do Linux (AF_PACKET / ETH_P_ALL) — nenhum framework de
captura (ex.: scapy, pcapy) é utilizado: os cabeçalhos Ethernet, IPv4 e TCP são
decodificados manualmente, byte a byte, a partir dos quadros crus.

Recursos:
  * filtra TCP pela porta do serviço (nos dois sentidos);
  * numera sequencialmente os pacotes com payload (os "números de pacote" da
    evidência) e imprime origem/destino, flags TCP e o payload legível;
  * extrai e destaca usuário/senha das mensagens "LOGIN ...";
  * opcionalmente grava um arquivo .pcap (formato libpcap clássico) que pode ser
    aberto no Wireshark — os frame numbers do Wireshark coincidem com a
    numeração impressa.

Requisitos: Linux e privilégio de root (CAP_NET_RAW).
Uso restrito ao laboratório isolado do grupo.

Exemplo:
  sudo python3 sniffer.py --interface lo --porta 5050 --pcap captura.pcap
"""

import argparse
import struct
import sys
import time

ETH_P_ALL = 0x0003       # captura todos os EtherTypes (big-endian ao criar)
ETH_P_IP = 0x0800        # EtherType de IPv4
ETH_HEADER_LEN = 14      # dst(6) + src(6) + ethertype(2)
PROTO_TCP = 6

# ---- Núcleo de parsing (independente de framework) -------------------------


def mac_para_str(seis_bytes: bytes) -> str:
    return ":".join(f"{b:02x}" for b in seis_bytes)


def ip_para_str(quatro_bytes: bytes) -> str:
    return ".".join(str(b) for b in quatro_bytes)


def flags_tcp_str(flags: int) -> str:
    nomes = [
        (0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"),
        (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG"),
    ]
    ativos = [nome for bit, nome in nomes if flags & bit]
    return ",".join(ativos) if ativos else "-"


def parse_ethernet(quadro: bytes):
    """Retorna (ethertype, offset_payload) ou None se curto demais."""
    if len(quadro) < ETH_HEADER_LEN:
        return None
    ethertype = struct.unpack("!H", quadro[12:14])[0]
    return ethertype, ETH_HEADER_LEN


def parse_ipv4(quadro: bytes, offset: int):
    """
    Decodifica o cabeçalho IPv4 (IHL variável).
    Retorna (protocolo, ip_origem, ip_destino, offset_payload) ou None.
    """
    if len(quadro) < offset + 20:
        return None
    primeiro = quadro[offset]
    versao = primeiro >> 4
    if versao != 4:
        return None
    ihl = (primeiro & 0x0F) * 4           # tamanho do cabeçalho IP em bytes
    if len(quadro) < offset + ihl:
        return None
    protocolo = quadro[offset + 9]
    ip_origem = ip_para_str(quadro[offset + 12:offset + 16])
    ip_destino = ip_para_str(quadro[offset + 16:offset + 20])
    return protocolo, ip_origem, ip_destino, offset + ihl


def parse_tcp(quadro: bytes, offset: int):
    """
    Decodifica o cabeçalho TCP (data offset variável).
    Retorna (porta_origem, porta_destino, flags, offset_payload) ou None.
    """
    if len(quadro) < offset + 20:
        return None
    porta_origem, porta_destino = struct.unpack("!HH", quadro[offset:offset + 4])
    # Byte 12 do cabeçalho TCP: data offset nos 4 bits altos (em palavras de 4B).
    data_offset = (quadro[offset + 12] >> 4) * 4
    flags = quadro[offset + 13]
    if len(quadro) < offset + data_offset:
        return None
    return porta_origem, porta_destino, flags, offset + data_offset


# ---- Gravação de .pcap (formato libpcap clássico) --------------------------


class EscritorPcap:
    """Grava quadros Ethernet crus em arquivo .pcap (linktype EN10MB)."""

    MAGIC = 0xA1B2C3D4
    VERSAO_MAJOR = 2
    VERSAO_MINOR = 4
    LINKTYPE_ETHERNET = 1

    def __init__(self, caminho: str):
        self._fp = open(caminho, "wb")
        # Global header (24 bytes).
        self._fp.write(struct.pack(
            "=IHHiIII",
            self.MAGIC,
            self.VERSAO_MAJOR, self.VERSAO_MINOR,
            0,                      # thiszone
            0,                      # sigfigs
            65535,                  # snaplen
            self.LINKTYPE_ETHERNET,
        ))

    def escrever(self, quadro: bytes, ts: float) -> None:
        segundos = int(ts)
        micros = int((ts - segundos) * 1_000_000)
        # Per-packet header (16 bytes) + dados.
        self._fp.write(struct.pack(
            "=IIII", segundos, micros, len(quadro), len(quadro)))
        self._fp.write(quadro)
        self._fp.flush()  # grava já; evita perda se o processo for interrompido

    def fechar(self) -> None:
        self._fp.close()


# ---- Laço principal de captura ---------------------------------------------


def extrair_credenciais(payload_texto: str):
    """
    Procura uma mensagem 'LOGIN <usuario> <senha>' no payload e devolve
    (usuario, senha), ou None. O protocolo é por linha, então varremos linhas.
    """
    for linha in payload_texto.replace("\r", "").split("\n"):
        partes = linha.strip().split()
        if len(partes) == 3 and partes[0].upper() == "LOGIN":
            return partes[1], partes[2]
    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Interceptador passivo com socket raw (AF_PACKET) — Fase 1."
    )
    parser.add_argument("--interface", default="lo",
                        help="interface a escutar (ex.: lo, eth0; padrão: lo)")
    parser.add_argument("--porta", type=int, default=5050,
                        help="porta TCP do serviço-alvo (padrão: 5050)")
    parser.add_argument("--pcap", default=None,
                        help="se informado, grava a captura neste arquivo .pcap")
    args = parser.parse_args()

    # Importa socket aqui para dar uma mensagem clara caso não seja Linux.
    import socket
    if not hasattr(socket, "AF_PACKET"):
        print("ERRO: AF_PACKET indisponivel. Este sniffer requer Linux "
              "(VM-observador). No Windows, use uma VM Linux.", file=sys.stderr)
        sys.exit(1)

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                             socket.ntohs(ETH_P_ALL))
        sock.bind((args.interface, 0))
    except PermissionError:
        print("ERRO: permissao negada. Execute como root "
              "(sudo python3 sniffer.py ...).", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"ERRO ao abrir socket raw na interface "
              f"'{args.interface}': {exc}", file=sys.stderr)
        sys.exit(1)

    pcap = EscritorPcap(args.pcap) if args.pcap else None

    print("=" * 72)
    print(" INTERCEPTADOR PASSIVO — Fase 1 (escuta em texto claro)")
    print(f" interface={args.interface}  porta-alvo={args.porta}  "
          f"pcap={args.pcap or 'nao'}")
    print(" quebra de confidencialidade: credenciais lidas sem participar da "
          "conexao")
    print("=" * 72)

    numero_pacote = 0
    try:
        while True:
            quadro = sock.recv(65535)
            ts = time.time()

            eth = parse_ethernet(quadro)
            if eth is None:
                continue
            ethertype, off = eth
            if ethertype != ETH_P_IP:
                continue

            ipv4 = parse_ipv4(quadro, off)
            if ipv4 is None:
                continue
            protocolo, ip_org, ip_dst, off = ipv4
            if protocolo != PROTO_TCP:
                continue

            tcp = parse_tcp(quadro, off)
            if tcp is None:
                continue
            porta_org, porta_dst, flags, off = tcp

            # Interessa somente o tráfego do serviço-alvo (ambos os sentidos).
            if args.porta not in (porta_org, porta_dst):
                continue

            payload = quadro[off:]
            if not payload:
                continue  # segmentos de controle sem dados são ignorados

            numero_pacote += 1
            if pcap:
                pcap.escrever(quadro, ts)

            texto = payload.decode("utf-8", errors="replace").rstrip("\n")
            hora = time.strftime("%H:%M:%S", time.localtime(ts))

            print(f"\n[pacote #{numero_pacote}] {hora}  "
                  f"{ip_org}:{porta_org} -> {ip_dst}:{porta_dst}  "
                  f"flags={flags_tcp_str(flags)}  len={len(payload)}")
            print(f"    payload: {texto!r}")

            cred = extrair_credenciais(texto)
            if cred:
                usuario, senha = cred
                print("    " + "!" * 56)
                print(f"    !!! CREDENCIAIS CAPTURADAS EM TEXTO CLARO")
                print(f"    !!!   usuario = {usuario}")
                print(f"    !!!   senha   = {senha}")
                print("    " + "!" * 56)

    except KeyboardInterrupt:
        print(f"\n[encerrando] {numero_pacote} pacote(s) com payload "
              f"capturado(s).")
    finally:
        if pcap:
            pcap.fechar()
            print(f"[pcap] captura gravada em '{args.pcap}'.")
        sock.close()


if __name__ == "__main__":
    main()
