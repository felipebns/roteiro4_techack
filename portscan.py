#!/usr/bin/env python3
"""Port scanner TCP (TCP connect) feito só com a biblioteca padrão do Python.

Para cada porta, tenta abrir uma conexão TCP completa com o destino e
classifica o resultado em: aberta, fechada (recusada), timeout ou erro.

Exemplo:
    python3 portscan.py localhost -p 20-25,80,8000 -t 0.5 -o resultado.json
"""

import argparse
import csv
import json
import socket
import sys
import time
from datetime import datetime

ABERTA = "aberta"    # handshake completo: algum serviço aceitou a conexão
FECHADA = "fechada"  # o destino respondeu recusando (RST): nada escutando ali
TIMEOUT = "timeout"  # nenhuma resposta dentro do tempo limite
ERRO = "erro"        # outra falha (rede inalcançável, permissão, etc.)


# ---------------------------------------------------------------------------
# 1. Receber e validar os parâmetros
# ---------------------------------------------------------------------------

def ler_porta(texto):
    """Converte um texto em número de porta, garantindo que está entre 1 e 65535."""
    try:
        porta = int(texto)
    except ValueError:
        raise ValueError(f"porta inválida: '{texto.strip()}' (use números de 1 a 65535)") from None
    if not 1 <= porta <= 65535:
        raise ValueError(f"porta fora do intervalo 1-65535: {porta}")
    return porta


def parse_portas(texto):
    """Interpreta '80', '20-25' ou combinações como '22,80,8000-8010'.

    Devolve a lista de portas na ordem informada, sem repetições.
    """
    portas = []
    for parte in texto.split(","):
        parte = parte.strip()
        if not parte:
            raise ValueError(f"lista de portas mal formada: '{texto}'")
        if "-" in parte:
            inicio, _, fim = parte.partition("-")
            if not inicio.strip() or not fim.strip():
                raise ValueError(f"intervalo incompleto: '{parte}' (use o formato início-fim)")
            inicio, fim = ler_porta(inicio), ler_porta(fim)
            if inicio > fim:
                raise ValueError(f"intervalo inválido: '{parte}' (início maior que o fim)")
            portas.extend(range(inicio, fim + 1))
        else:
            portas.append(ler_porta(parte))
    return list(dict.fromkeys(portas))  # remove repetidas mantendo a ordem


def resolver_destino(destino):
    """Converte hostname ou IP em um endereço IPv4. Erro se não for possível."""
    if not destino.strip():
        raise ValueError("destino vazio")
    try:
        return socket.gethostbyname(destino)
    except (OSError, UnicodeError):
        raise ValueError(f"destino inválido ou não encontrado: '{destino}'") from None


def timeout_valido(texto):
    """Usado pelo argparse para aceitar apenas timeouts positivos."""
    try:
        valor = float(texto)
    except ValueError:
        raise argparse.ArgumentTypeError(f"timeout inválido: '{texto}'") from None
    if not 0 < valor <= 60:
        raise argparse.ArgumentTypeError("o timeout deve ser maior que 0 e no máximo 60 segundos")
    return valor


def ler_argumentos(argv=None):
    parser = argparse.ArgumentParser(
        description="Port scanner TCP (connect scan). Use apenas em sistemas próprios ou autorizados.",
        epilog="exemplo: python3 portscan.py localhost -p 20-25,80,8000 -t 0.5 -o resultado.csv",
    )
    parser.add_argument("destino", help="IP ou hostname do alvo (ex.: 127.0.0.1, localhost)")
    parser.add_argument("-p", "--portas", required=True,
                        help="porta (80), intervalo (20-25) ou lista (22,80,8000-8010)")
    parser.add_argument("-t", "--timeout", type=timeout_valido, default=1.0,
                        help="tempo limite de cada tentativa, em segundos (padrão: 1.0)")
    parser.add_argument("-o", "--saida",
                        help="salva os resultados em arquivo .csv ou .json")
    parser.add_argument("-a", "--abertas", action="store_true",
                        help="mostra na tela apenas as portas abertas")

    args = parser.parse_args(argv)

    # validações feitas aqui para que os erros apareçam junto com a ajuda de uso
    try:
        args.lista_portas = parse_portas(args.portas)
        args.ip = resolver_destino(args.destino)
    except ValueError as erro:
        parser.error(str(erro))
    if args.saida and not args.saida.lower().endswith((".csv", ".json")):
        parser.error("o arquivo de saída precisa terminar em .csv ou .json")
    return args


# ---------------------------------------------------------------------------
# 2. Tentar a conexão e 3. interpretar o resultado
# ---------------------------------------------------------------------------

def tentar_conexao(ip, porta, timeout):
    """Tenta o handshake TCP. Devolve None se conectou, ou a exceção que ocorreu.

    O 'with' garante que o socket é fechado em qualquer caso
    (sucesso, erro ou Ctrl+C no meio da tentativa).
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


def servico_provavel(porta):
    """Nome normalmente associado à porta (tabela do sistema).

    É só um palpite: não confirma qual serviço está realmente rodando.
    """
    try:
        return socket.getservbyport(porta, "tcp")
    except OSError:
        return "-"


# ---------------------------------------------------------------------------
# 4. Registrar e apresentar
# ---------------------------------------------------------------------------

FORMATO_LINHA = "{destino:<16} {porta:>5}  {resultado:<10} {servico:<18} {detalhe}"


def imprimir_cabecalho(args):
    print(f"Destino: {args.destino} ({args.ip})")
    print(f"Portas: {len(args.lista_portas)} | Timeout: {args.timeout}s | "
          f"Início: {datetime.now():%Y-%m-%d %H:%M:%S}")
    print()
    print(FORMATO_LINHA.format(destino="DESTINO", porta="PORTA", resultado="RESULTADO",
                               servico="SERVIÇO (palpite)", detalhe="DETALHE"))


def imprimir_resumo(resultados, total, duracao, interrompido):
    contagem = {estado: 0 for estado in (ABERTA, FECHADA, TIMEOUT, ERRO)}
    for r in resultados:
        contagem[r["resultado"]] += 1
    abertas = [str(r["porta"]) for r in resultados if r["resultado"] == ABERTA]

    print()
    if interrompido:
        print(f"Varredura interrompida pelo usuário: {len(resultados)} de {total} portas testadas.")
    print(f"Resumo: {contagem[ABERTA]} aberta(s), {contagem[FECHADA]} fechada(s), "
          f"{contagem[TIMEOUT]} timeout, {contagem[ERRO]} erro | tempo total: {duracao:.2f}s")
    print("Portas abertas: " + (", ".join(abertas) if abertas else "nenhuma"))


def exportar(caminho, args, resultados, duracao, interrompido):
    """Salva os resultados em CSV (uma linha por porta) ou JSON (com metadados)."""
    if caminho.lower().endswith(".csv"):
        with open(caminho, "w", newline="", encoding="utf-8") as arquivo:
            campos = ["destino", "ip", "porta", "resultado", "servico", "detalhe"]
            escritor = csv.DictWriter(arquivo, fieldnames=campos)
            escritor.writeheader()
            escritor.writerows(resultados)
    else:
        dados = {
            "destino": args.destino,
            "ip": args.ip,
            "timeout_s": args.timeout,
            "data": datetime.now().isoformat(timespec="seconds"),
            "duracao_s": round(duracao, 3),
            "interrompido": interrompido,
            "resultados": resultados,
        }
        with open(caminho, "w", encoding="utf-8") as arquivo:
            json.dump(dados, arquivo, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Programa principal
# ---------------------------------------------------------------------------

def main(argv=None):
    args = ler_argumentos(argv)
    imprimir_cabecalho(args)

    resultados = []
    interrompido = False
    inicio = time.perf_counter()
    try:
        for porta in args.lista_portas:
            resultado, detalhe = interpretar(tentar_conexao(args.ip, porta, args.timeout))
            registro = {
                "destino": args.destino,
                "ip": args.ip,
                "porta": porta,
                "resultado": resultado,
                "servico": servico_provavel(porta),
                "detalhe": detalhe,
            }
            resultados.append(registro)
            if resultado == ABERTA or not args.abertas:
                print(FORMATO_LINHA.format(**registro), flush=True)
    except KeyboardInterrupt:
        interrompido = True
    duracao = time.perf_counter() - inicio

    imprimir_resumo(resultados, len(args.lista_portas), duracao, interrompido)

    if args.saida:
        try:
            exportar(args.saida, args, resultados, duracao, interrompido)
            print(f"Resultados salvos em: {args.saida}")
        except OSError as erro:
            sys.stdout.flush()  # garante que o resumo aparece antes da mensagem de erro
            print(f"Erro ao salvar '{args.saida}': {erro.strerror or erro}", file=sys.stderr)
            return 1

    return 130 if interrompido else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:  # Ctrl+C fora da varredura (ex.: resolvendo o DNS)
        print("\nInterrompido pelo usuário.", file=sys.stderr)
        sys.exit(130)
