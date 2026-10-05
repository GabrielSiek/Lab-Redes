#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Servidor do serviço-alvo — Fase 1 (Laboratório de Redes / PUCRS).

Serviço de autenticação INTENCIONALMENTE INSEGURO: as credenciais trafegam
em TEXTO CLARO sobre TCP, sem cifragem e sem hash. O objetivo é servir de alvo
para o interceptador passivo (sniffer.py) demonstrar a quebra de
confidencialidade. A proteção (TLS + hash de senha) é assunto da Fase 3.

Uso restrito a um laboratório isolado (VMs do próprio grupo).

Protocolo (texto, uma mensagem por linha, terminada em '\\n'):
  S -> C  : "200 AUTH-SERVICE v1 pronto"            (banner, ao conectar)
  C -> S  : "LOGIN <usuario> <senha>"
  S -> C  : "200 OK bem-vindo <usuario>"            (credenciais válidas)
            "401 ERRO credenciais invalidas"        (credenciais inválidas)
            "400 ERRO comando malformado"           (sintaxe inválida)
  C -> S  : "QUIT"
  S -> C  : "221 tchau"

Concorrência: uma thread por cliente (base já pronta para a Fase 2).

Somente a biblioteca padrão de sockets é usada (sem frameworks).
"""

import argparse
import os
import socket
import threading
from datetime import datetime

# Codificação do protocolo: ASCII/latin-1 é suficiente; usamos UTF-8 por
# robustez, mantendo o conteúdo legível.
ENCODING = "utf-8"
PORTA_PADRAO = 5050


def agora() -> str:
    """Horário local formatado, para os logs do servidor."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def carregar_usuarios(caminho: str) -> dict:
    """
    Lê o arquivo de credenciais no formato 'usuario:senha' (uma por linha).

    As senhas ficam em texto claro de propósito nesta fase. Linhas vazias e
    linhas iniciadas por '#' são ignoradas.
    """
    usuarios = {}
    if not os.path.exists(caminho):
        print(f"[{agora()}] AVISO: arquivo de usuarios '{caminho}' nao "
              f"encontrado; nenhum usuario carregado.")
        return usuarios

    with open(caminho, "r", encoding=ENCODING) as fp:
        for linha in fp:
            linha = linha.strip()
            if not linha or linha.startswith("#"):
                continue
            if ":" not in linha:
                continue
            usuario, senha = linha.split(":", 1)
            usuarios[usuario] = senha
    print(f"[{agora()}] {len(usuarios)} usuario(s) carregado(s) de '{caminho}'.")
    return usuarios


def enviar_linha(conexao: socket.socket, texto: str) -> None:
    """Envia uma mensagem do protocolo terminada por '\\n'."""
    conexao.sendall((texto + "\n").encode(ENCODING))


def tratar_cliente(conexao: socket.socket, endereco, usuarios: dict) -> None:
    """
    Atende uma conexão de cliente até QUIT/desconexão.

    Mantém um buffer de bytes e processa o fluxo linha a linha, pois o TCP não
    preserva fronteiras de mensagem.
    """
    ip, porta = endereco[0], endereco[1]
    print(f"[{agora()}] + conexao de {ip}:{porta}")

    try:
        enviar_linha(conexao, "200 AUTH-SERVICE v1 pronto")
        buffer = b""

        while True:
            dados = conexao.recv(4096)
            if not dados:
                break  # cliente fechou a conexão
            buffer += dados

            # Processa todas as linhas completas presentes no buffer.
            while b"\n" in buffer:
                linha_bytes, buffer = buffer.split(b"\n", 1)
                linha = linha_bytes.decode(ENCODING, errors="replace").strip()
                if not linha:
                    continue

                partes = linha.split()
                comando = partes[0].upper()

                if comando == "LOGIN":
                    if len(partes) != 3:
                        enviar_linha(conexao, "400 ERRO comando malformado")
                        print(f"[{agora()}]   {ip}:{porta} LOGIN malformado")
                        continue

                    usuario, senha = partes[1], partes[2]
                    # Credenciais recebidas em texto claro.
                    if usuarios.get(usuario) == senha:
                        enviar_linha(conexao, f"200 OK bem-vindo {usuario}")
                        print(f"[{agora()}]   {ip}:{porta} LOGIN OK "
                              f"usuario='{usuario}'")
                    else:
                        enviar_linha(conexao, "401 ERRO credenciais invalidas")
                        print(f"[{agora()}]   {ip}:{porta} LOGIN FALHOU "
                              f"usuario='{usuario}'")

                elif comando == "QUIT":
                    enviar_linha(conexao, "221 tchau")
                    print(f"[{agora()}]   {ip}:{porta} QUIT")
                    return

                else:
                    enviar_linha(conexao, "400 ERRO comando desconhecido")
                    print(f"[{agora()}]   {ip}:{porta} comando "
                          f"desconhecido: '{comando}'")

    except ConnectionResetError:
        print(f"[{agora()}]   {ip}:{porta} conexao resetada pelo cliente")
    except Exception as exc:  # um cliente não derruba os demais
        print(f"[{agora()}]   {ip}:{porta} erro: {exc}")
    finally:
        conexao.close()
        print(f"[{agora()}] - encerrada conexao de {ip}:{porta}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Servidor do serviço-alvo (login em texto claro) — Fase 1."
    )
    parser.add_argument("--host", default="0.0.0.0",
                        help="endereço de bind (padrão: 0.0.0.0)")
    parser.add_argument("--porta", type=int, default=PORTA_PADRAO,
                        help=f"porta TCP (padrão: {PORTA_PADRAO})")
    parser.add_argument("--usuarios", default=os.path.join(
                            os.path.dirname(os.path.abspath(__file__)),
                            "usuarios.txt"),
                        help="arquivo de credenciais (usuario:senha por linha)")
    args = parser.parse_args()

    usuarios = carregar_usuarios(args.usuarios)

    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind((args.host, args.porta))
    servidor.listen(16)

    print(f"[{agora()}] AUTH-SERVICE escutando em {args.host}:{args.porta} "
          f"(TEXTO CLARO — apenas para laboratorio isolado)")

    try:
        while True:
            conexao, endereco = servidor.accept()
            thread = threading.Thread(
                target=tratar_cliente,
                args=(conexao, endereco, usuarios),
                daemon=True,
            )
            thread.start()
    except KeyboardInterrupt:
        print(f"\n[{agora()}] encerrando servidor...")
    finally:
        servidor.close()


if __name__ == "__main__":
    main()
