#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gerar_hashes.py — Fase 3 (Laboratório de Redes / PUCRS).

Converte a base de credenciais em TEXTO CLARO da Fase 1 (usuarios.txt) em uma
base com SENHAS PROTEGIDAS POR HASH, eliminando o armazenamento de senha legível
que o sniffer da Fase 1 explorava no servidor.

Esquema: PBKDF2-HMAC-SHA256 com SALT aleatório por usuário.
  - PBKDF2 aplica a função de hash muitas vezes (iterações) para encarecer a
    quebra por força bruta.
  - O salt (aleatório e único por usuário) impede ataques de rainbow table e
    faz com que dois usuários com a MESMA senha tenham hashes diferentes.
  - hmac.compare_digest (usado no servidor) compara em tempo constante,
    evitando ataques de temporização.

Formato de saída (uma linha por usuário):
  usuario:pbkdf2_sha256$<iteracoes>$<salt_base64>$<hash_base64>

Somente a biblioteca padrão é usada.

Uso:  python3 gerar_hashes.py [--entrada ../usuarios.txt] [--saida usuarios_hash.txt]
"""
import argparse
import base64
import hashlib
import os

ITERACOES = 200_000
TAM_SALT = 16  # bytes
ALGORITMO = "pbkdf2_sha256"


def hash_senha(senha: str, salt: bytes = None, iteracoes: int = ITERACOES) -> str:
    """Gera a string de verificação '<alg>$<iter>$<salt_b64>$<hash_b64>'."""
    if salt is None:
        salt = os.urandom(TAM_SALT)
    dk = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), salt, iteracoes)
    return (f"{ALGORITMO}${iteracoes}$"
            f"{base64.b64encode(salt).decode()}$"
            f"{base64.b64encode(dk).decode()}")


def main() -> None:
    aqui = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(
        description="Gera usuarios_hash.txt (PBKDF2) a partir de usuarios.txt.")
    parser.add_argument("--entrada",
                        default=os.path.join(aqui, "..", "usuarios.txt"),
                        help="base em texto claro (usuario:senha)")
    parser.add_argument("--saida",
                        default=os.path.join(aqui, "usuarios_hash.txt"),
                        help="base protegida de saída")
    args = parser.parse_args()

    linhas_saida = [
        "# Base de credenciais PROTEGIDA — Fase 3",
        "# Formato: usuario:pbkdf2_sha256$<iteracoes>$<salt_b64>$<hash_b64>",
        "# As senhas NAO sao recuperaveis a partir deste arquivo.",
    ]
    total = 0
    with open(args.entrada, "r", encoding="utf-8") as fp:
        for linha in fp:
            linha = linha.strip()
            if not linha or linha.startswith("#") or ":" not in linha:
                continue
            usuario, senha = linha.split(":", 1)
            linhas_saida.append(f"{usuario}:{hash_senha(senha)}")
            total += 1

    with open(args.saida, "w", encoding="utf-8") as fp:
        fp.write("\n".join(linhas_saida) + "\n")

    print(f"{total} credencial(is) protegida(s) gravada(s) em '{args.saida}'.")
    print("As senhas em texto claro NAO foram copiadas para a saida.")


if __name__ == "__main__":
    main()
