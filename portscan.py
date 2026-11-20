#!/usr/bin/env python3
"""Port scanner TCP (TCP connect) feito só com a biblioteca padrão do Python.

Para cada porta, tenta abrir uma conexão TCP completa com o destino.
"""

import argparse
import socket
import sys


def parse_portas(texto):
    """Interpreta '80' ou um intervalo '20-25'."""
    if "-" in texto:
        inicio, fim = texto.split("-")
        return list(range(int(inicio), int(fim) + 1))
    return [int(texto)]


def ler_argumentos(argv=None):
    parser = argparse.ArgumentParser(description="Port scanner TCP (connect scan).")
    parser.add_argument("destino", help="IP ou hostname do alvo (ex.: 127.0.0.1, localhost)")
    parser.add_argument("-p", "--portas", required=True, help="porta (80) ou intervalo (20-25)")
    return parser.parse_args(argv)


def porta_aberta(ip, porta, timeout=1.0):
    """Devolve True se conseguiu completar o handshake TCP com a porta."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((ip, porta))
            return True
        except OSError:
            return False


def main(argv=None):
    args = ler_argumentos(argv)
    ip = socket.gethostbyname(args.destino)
    print(f"Destino: {args.destino} ({ip})")
    for porta in parse_portas(args.portas):
        estado = "aberta" if porta_aberta(ip, porta) else "fechada"
        print(f"{porta:>5}  {estado}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
