#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cliente do serviço-alvo — Fase 1 (Laboratório de Redes / PUCRS).

Conecta ao servidor de autenticação e envia usuário e senha em TEXTO CLARO.
Dois modos:
  * não interativo: --usuario e --senha fornecidos por argumento (bom para
    scripts de demonstração);
  * interativo: solicita usuário e senha no terminal.

Somente a biblioteca padrão de sockets é usada (sem frameworks).
"""

import argparse
import getpass
import socket

ENCODING = "utf-8"
PORTA_PADRAO = 5050


def ler_linha(sock_file) -> str:
    """Lê uma linha de resposta do servidor (já sem o '\\n')."""
    linha = sock_file.readline()
    return linha.rstrip("\n") if linha else ""


def sessao(host: str, porta: int, usuario: str, senha: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, porta))
        # Envolve o socket num objeto arquivo para leitura linha a linha.
        sock_file = sock.makefile("r", encoding=ENCODING, newline="\n")

        banner = ler_linha(sock_file)
        print(f"<< {banner}")

        # A credencial vai pela rede SEM cifragem 
        comando = f"LOGIN {usuario} {senha}"
        print(f">> {comando}")
        sock.sendall((comando + "\n").encode(ENCODING))

        resposta = ler_linha(sock_file)
        print(f"<< {resposta}")

        print(">> QUIT")
        sock.sendall(b"QUIT\n")
        despedida = ler_linha(sock_file)
        print(f"<< {despedida}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cliente do serviço-alvo (login em texto claro) — Fase 1."
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="endereço do servidor (padrão: 127.0.0.1)")
    parser.add_argument("--porta", type=int, default=PORTA_PADRAO,
                        help=f"porta TCP (padrão: {PORTA_PADRAO})")
    parser.add_argument("--usuario", help="nome de usuário (modo não interativo)")
    parser.add_argument("--senha", help="senha (modo não interativo)")
    args = parser.parse_args()

    usuario = args.usuario if args.usuario is not None else input("Usuario: ")
    if args.senha is not None:
        senha = args.senha
    else:
        senha = getpass.getpass("Senha: ")

    sessao(args.host, args.porta, usuario, senha)


if __name__ == "__main__":
    main()
