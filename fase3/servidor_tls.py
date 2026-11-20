#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Servidor do serviço-alvo PROTEGIDO — Fase 3 (Laboratório de Redes / PUCRS).

É o MESMO serviço de autenticação da Fase 1, mas com a defesa aplicada:

  1. CONFIDENCIALIDADE + INTEGRIDADE: o socket TCP é envolvido em TLS
     (ssl.PROTOCOL_TLS_SERVER). Todo o tráfego passa cifrado e autenticado,
     então o sniffer passivo da Fase 1 deixa de ler as credenciais e um MITM
     não consegue alterar bytes sem quebrar o TLS.

  2. AUTENTICAÇÃO DO SERVIDOR: o servidor apresenta um certificado assinado pela
     CA do laboratório. O cliente valida esse certificado; se um MITM tentar se
     passar pelo servidor com outro certificado, a validação falha no cliente.

  3. SENHAS COM HASH: as credenciais não ficam mais em texto claro. A base é
     usuarios_hash.txt (PBKDF2-HMAC-SHA256 + salt por usuário). A verificação
     usa hmac.compare_digest (tempo constante).

O PROTOCOLO de aplicação é idêntico ao da Fase 1 (banner, LOGIN, 200/401, QUIT,
221) — só o transporte mudou. Assim o relatório mostra a MESMA aplicação antes
(insegura) e depois (protegida).

Somente a biblioteca padrão é usada (socket, ssl, hashlib, hmac, threading).

Uso:
  python3 servidor_tls.py --cert certs/servidor.crt --chave certs/servidor.key \\
      --usuarios usuarios_hash.txt --host 0.0.0.0 --porta 5050
"""
import argparse
import base64
import hashlib
import hmac
import os
import socket
import ssl
import threading
from datetime import datetime

ENCODING = "utf-8"
PORTA_PADRAO = 5050
TIMEOUT_SESSAO = 30  # segundos sem dados antes de encerrar (com log)


def agora() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ----------------------------- Credenciais com hash ------------------------

def carregar_usuarios(caminho: str) -> dict:
    """Lê usuarios_hash.txt no formato 'usuario:pbkdf2_sha256$iter$salt$hash'."""
    usuarios = {}
    if not os.path.exists(caminho):
        print(f"[{agora()}] AVISO: base '{caminho}' nao encontrada; "
              f"nenhum usuario carregado.")
        return usuarios
    with open(caminho, "r", encoding=ENCODING) as fp:
        for linha in fp:
            linha = linha.strip()
            if not linha or linha.startswith("#") or ":" not in linha:
                continue
            usuario, verificador = linha.split(":", 1)
            usuarios[usuario] = verificador
    print(f"[{agora()}] {len(usuarios)} credencial(is) com hash carregada(s) "
          f"de '{caminho}'.")
    return usuarios


def senha_confere(senha_recebida: str, verificador: str) -> bool:
    """
    Recalcula o PBKDF2 da senha recebida com o MESMO salt/iterações guardados e
    compara em tempo constante. Nunca manuseia a senha original (não existe).
    """
    try:
        algoritmo, iteracoes_s, salt_b64, hash_b64 = verificador.split("$")
        if algoritmo != "pbkdf2_sha256":
            return False
        iteracoes = int(iteracoes_s)
        salt = base64.b64decode(salt_b64)
        esperado = base64.b64decode(hash_b64)
    except (ValueError, Exception):
        return False
    calculado = hashlib.pbkdf2_hmac(
        "sha256", senha_recebida.encode(ENCODING), salt, iteracoes)
    return hmac.compare_digest(calculado, esperado)


# ----------------------------- Protocolo (= Fase 1) ------------------------

def enviar_linha(conexao: ssl.SSLSocket, texto: str) -> None:
    conexao.sendall((texto + "\n").encode(ENCODING))


def tratar_cliente(conexao: ssl.SSLSocket, endereco, usuarios: dict) -> None:
    ip, porta = endereco[0], endereco[1]
    cifra = conexao.cipher()
    cifra_txt = f"{cifra[0]} ({cifra[1]})" if cifra else "desconhecida"
    print(f"[{agora()}] + conexao TLS de {ip}:{porta} | cifra={cifra_txt}")

    conexao.settimeout(TIMEOUT_SESSAO)
    try:
        enviar_linha(conexao, "200 AUTH-SERVICE v1 pronto")
        buffer = b""
        while True:
            try:
                dados = conexao.recv(4096)
            except socket.timeout:
                # Robustez: o encerramento por timeout agora É REGISTRADO.
                print(f"[{agora()}]   {ip}:{porta} sessao encerrada por "
                      f"inatividade ({TIMEOUT_SESSAO}s sem dados)")
                enviar_linha_silencioso(conexao, "408 ERRO tempo esgotado")
                break
            if not dados:
                break
            buffer += dados
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
                    verificador = usuarios.get(usuario)
                    if verificador and senha_confere(senha, verificador):
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
                    print(f"[{agora()}]   {ip}:{porta} comando desconhecido: "
                          f"'{comando}'")
    except ssl.SSLError as exc:
        print(f"[{agora()}]   {ip}:{porta} erro TLS: {exc}")
    except ConnectionResetError:
        print(f"[{agora()}]   {ip}:{porta} conexao resetada pelo cliente")
    except Exception as exc:
        print(f"[{agora()}]   {ip}:{porta} erro: {exc}")
    finally:
        try:
            conexao.close()
        except Exception:
            pass
        print(f"[{agora()}] - encerrada conexao de {ip}:{porta}")


def enviar_linha_silencioso(conexao, texto: str) -> None:
    """Tenta enviar uma linha, ignorando falhas (usado em encerramentos)."""
    try:
        conexao.sendall((texto + "\n").encode(ENCODING))
    except Exception:
        pass


# ----------------------------- Programa principal --------------------------

def main() -> None:
    aqui = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(
        description="Servidor do serviço-alvo PROTEGIDO (TLS + hash) — Fase 3.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--porta", type=int, default=PORTA_PADRAO)
    parser.add_argument("--cert", default=os.path.join(aqui, "certs", "servidor.crt"),
                        help="certificado do servidor (assinado pela CA)")
    parser.add_argument("--chave", default=os.path.join(aqui, "certs", "servidor.key"),
                        help="chave privada do servidor")
    parser.add_argument("--usuarios", default=os.path.join(aqui, "usuarios_hash.txt"),
                        help="base de credenciais com hash")
    args = parser.parse_args()

    usuarios = carregar_usuarios(args.usuarios)

    # Contexto TLS do lado servidor: apresenta o certificado ao cliente.
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        contexto.load_cert_chain(certfile=args.cert, keyfile=args.chave)
    except (FileNotFoundError, ssl.SSLError) as exc:
        print(f"[{agora()}] ERRO ao carregar certificado/chave: {exc}")
        print("  Gere os certificados antes: ./gerar_certificados.sh")
        raise SystemExit(1)
    contexto.minimum_version = ssl.TLSVersion.TLSv1_2

    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind((args.host, args.porta))
    servidor.listen(16)

    print(f"[{agora()}] AUTH-SERVICE (TLS) escutando em {args.host}:{args.porta}")
    print(f"[{agora()}] certificado='{args.cert}'  TLS>=1.2")

    try:
        while True:
            bruto, endereco = servidor.accept()
            try:
                conexao = contexto.wrap_socket(bruto, server_side=True)
            except ssl.SSLError as exc:
                # Handshake falhou (ex.: cliente desistiu ao não validar cert).
                print(f"[{agora()}]   {endereco[0]}:{endereco[1]} handshake TLS "
                      f"falhou: {exc}")
                bruto.close()
                continue
            threading.Thread(target=tratar_cliente,
                             args=(conexao, endereco, usuarios),
                             daemon=True).start()
    except KeyboardInterrupt:
        print(f"\n[{agora()}] encerrando servidor...")
    finally:
        servidor.close()


if __name__ == "__main__":
    main()
