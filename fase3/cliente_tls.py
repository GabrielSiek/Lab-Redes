#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cliente do serviço-alvo PROTEGIDO — Fase 3 (Laboratório de Redes / PUCRS).

É o MESMO cliente da Fase 1, agora falando TLS e VALIDANDO a identidade do
servidor antes de enviar a credencial:

  - confia apenas na CA do laboratório (ca.crt);
  - exige certificado do servidor (CERT_REQUIRED) e verifica o nome
    (check_hostname) contra 'servidor-auth' (o SAN do certificado legítimo).

Consequência para a segurança:
  - um sniffer passivo só vê bytes cifrados (não lê a senha);
  - um MITM que tente se passar pelo servidor apresenta um certificado que a CA
    não assinou -> a validação FALHA e o cliente ABORTA antes de enviar a senha.
    Esse erro de validação é o SINAL DE DETECÇÃO do ataque.

Somente a biblioteca padrão é usada (socket, ssl).

Uso:
  python3 cliente_tls.py --host 10.0.0.20 --porta 5050 --cafile certs/ca.crt \\
      --usuario alice --senha S3nh4Secreta
"""
import argparse
import getpass
import os
import socket
import ssl
import sys

ENCODING = "utf-8"
PORTA_PADRAO = 5050
NOME_SERVIDOR = "servidor-auth"  # precisa casar com o SAN do certificado


def ler_linha(sock_file) -> str:
    linha = sock_file.readline()
    return linha.rstrip("\n") if linha else ""


def sessao(host: str, porta: int, cafile: str, servidor_nome: str,
           usuario: str, senha: str) -> int:
    # Contexto TLS do lado cliente: valida o servidor contra a CA do laboratório.
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    contexto.minimum_version = ssl.TLSVersion.TLSv1_2
    contexto.check_hostname = True
    contexto.verify_mode = ssl.CERT_REQUIRED
    try:
        contexto.load_verify_locations(cafile=cafile)
    except (FileNotFoundError, ssl.SSLError) as exc:
        print(f"ERRO ao carregar a CA '{cafile}': {exc}", file=sys.stderr)
        return 2

    bruto = socket.create_connection((host, porta), timeout=10)
    try:
        # O handshake TLS (e a validação do certificado) acontece aqui.
        conexao = contexto.wrap_socket(bruto, server_hostname=servidor_nome)
    except ssl.SSLCertVerificationError as exc:
        print("=" * 64)
        print(" ATAQUE DETECTADO / CONEXAO ABORTADA")
        print(" A validacao do certificado do servidor FALHOU:")
        print(f"   {exc}")
        print(" O cliente NAO enviou a credencial. Possiveis causas: MITM se")
        print(" passando pelo servidor, ou certificado invalido/expirado.")
        print("=" * 64)
        bruto.close()
        return 3
    except ssl.SSLError as exc:
        print(f"ERRO de TLS no handshake: {exc}", file=sys.stderr)
        bruto.close()
        return 3

    with conexao:
        cert = conexao.getpeercert()
        cn = dict(x[0] for x in cert.get("subject", ()))
        print(f"[TLS OK] servidor autenticado: CN={cn.get('commonName')} | "
              f"cifra={conexao.cipher()[0]}")
        sock_file = conexao.makefile("r", encoding=ENCODING, newline="\n")

        print(f"<< {ler_linha(sock_file)}")           # banner
        comando = f"LOGIN {usuario} {senha}"
        print(f">> {comando}  (agora cifrado pelo TLS)")
        conexao.sendall((comando + "\n").encode(ENCODING))
        print(f"<< {ler_linha(sock_file)}")           # 200/401

        print(">> QUIT")
        conexao.sendall(b"QUIT\n")
        print(f"<< {ler_linha(sock_file)}")           # 221
    return 0


def main() -> None:
    aqui = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(
        description="Cliente do serviço-alvo PROTEGIDO (valida TLS) — Fase 3.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--porta", type=int, default=PORTA_PADRAO)
    parser.add_argument("--cafile", default=os.path.join(aqui, "certs", "ca.crt"),
                        help="CA em que o cliente confia")
    parser.add_argument("--servidor-nome", default=NOME_SERVIDOR,
                        help="nome esperado no certificado do servidor (SAN)")
    parser.add_argument("--usuario")
    parser.add_argument("--senha")
    args = parser.parse_args()

    usuario = args.usuario if args.usuario is not None else input("Usuario: ")
    senha = args.senha if args.senha is not None else getpass.getpass("Senha: ")

    codigo = sessao(args.host, args.porta, args.cafile, args.servidor_nome,
                    usuario, senha)
    sys.exit(codigo)


if __name__ == "__main__":
    main()
