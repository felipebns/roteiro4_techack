#!/usr/bin/env python3
"""Port scanner TCP (TCP connect) feito só com a biblioteca padrão do Python.

Para cada porta, tenta abrir uma conexão TCP completa com o destino e
classifica o resultado em: aberta, fechada (recusada), timeout ou erro.

Exemplo:
    python3 portscan.py localhost -p 20-25 -t 0.5
"""

import argparse
import socket
import sys
from datetime import datetime

ABERTA = "aberta"    # handshake completo: algum serviço aceitou a conexão
FECHADA = "fechada"  # o destino respondeu recusando (RST): nada escutando ali
TIMEOUT = "timeout"  # nenhuma resposta dentro do tempo limite
ERRO = "erro"        # outra falha (rede inalcançável, permissão, etc.)


# ---------------------------------------------------------------------------
# 1. Receber os parâmetros
# ---------------------------------------------------------------------------

def parse_portas(texto):
    """Interpreta '80' ou um intervalo '20-25'."""
    if "-" in texto:
        inicio, fim = texto.split("-")
        return list(range(int(inicio), int(fim) + 1))
    return [int(texto)]


def ler_argumentos(argv=None):
    parser = argparse.ArgumentParser(
        description="Port scanner TCP (connect scan). Use apenas em sistemas próprios ou autorizados.",
    )
    parser.add_argument("destino", help="IP ou hostname do alvo (ex.: 127.0.0.1, localhost)")
    parser.add_argument("-p", "--portas", required=True, help="porta (80) ou intervalo (20-25)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                        help="tempo limite de cada tentativa, em segundos (padrão: 1.0)")
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# 2. Tentar a conexão e 3. interpretar o resultado
# ---------------------------------------------------------------------------

def tentar_conexao(ip, porta, timeout):
    """Tenta o handshake TCP. Devolve None se conectou, ou a exceção que ocorreu.

    O 'with' garante que o socket é fechado em qualquer caso.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((ip, porta))
            return None
        except OSError as erro:
            return erro


def interpretar(erro):
    """Traduz o retorno de tentar_conexao em (resultado, detalhe)."""
    if erro is None:
        return ABERTA, "conexão estabelecida"
    if isinstance(erro, ConnectionRefusedError):
        return FECHADA, "conexão recusada"
    if isinstance(erro, (socket.timeout, TimeoutError)):  # iguais a partir do Python 3.10
        return TIMEOUT, "sem resposta no tempo limite"
    return ERRO, erro.strerror or str(erro)


# ---------------------------------------------------------------------------
# 4. Registrar e apresentar
# ---------------------------------------------------------------------------

FORMATO_LINHA = "{destino:<16} {porta:>5}  {resultado:<10} {detalhe}"


def imprimir_cabecalho(args):
    print(f"Destino: {args.destino} ({args.ip})")
    print(f"Portas: {len(args.lista_portas)} | Timeout: {args.timeout}s | "
          f"Início: {datetime.now():%Y-%m-%d %H:%M:%S}")
    print()
    print(FORMATO_LINHA.format(destino="DESTINO", porta="PORTA", resultado="RESULTADO",
                               detalhe="DETALHE"))


def imprimir_resumo(resultados):
    contagem = {estado: 0 for estado in (ABERTA, FECHADA, TIMEOUT, ERRO)}
    for r in resultados:
        contagem[r["resultado"]] += 1
    abertas = [str(r["porta"]) for r in resultados if r["resultado"] == ABERTA]

    print()
    print(f"Resumo: {contagem[ABERTA]} aberta(s), {contagem[FECHADA]} fechada(s), "
          f"{contagem[TIMEOUT]} timeout, {contagem[ERRO]} erro")
    print("Portas abertas: " + (", ".join(abertas) if abertas else "nenhuma"))


# ---------------------------------------------------------------------------
# Programa principal
# ---------------------------------------------------------------------------

def main(argv=None):
    args = ler_argumentos(argv)
    args.lista_portas = parse_portas(args.portas)
    args.ip = socket.gethostbyname(args.destino)
    imprimir_cabecalho(args)

    resultados = []
    for porta in args.lista_portas:
        resultado, detalhe = interpretar(tentar_conexao(args.ip, porta, args.timeout))
        registro = {
            "destino": args.destino,
            "ip": args.ip,
            "porta": porta,
            "resultado": resultado,
            "detalhe": detalhe,
        }
        resultados.append(registro)
        print(FORMATO_LINHA.format(**registro), flush=True)

    imprimir_resumo(resultados)
    return 0


if __name__ == "__main__":
    sys.exit(main())
