"""
Ambiente de teste local para o portscan.py (testado no Linux).
Sobe duas portas em 127.0.0.1:
  - porta aberta (padrão 8080): aceita conexões normalmente;
  - porta silenciosa (padrão 9090): a fila de conexões pendentes fica cheia
    de propósito, então o kernel descarta novos pedidos de conexão (SYN) sem
    responder. Quem tenta conectar não recebe nada e cai em TIMEOUT, como
    aconteceria com uma porta protegida por firewall que descarta pacotes.

Encerrar com Ctrl+C.
"""

import argparse
import socket


def main():
    parser = argparse.ArgumentParser(description="Sobe portas de teste em 127.0.0.1")
    parser.add_argument("--aberta", type=int, default=8080, help="porta que aceita conexões")
    parser.add_argument("--silenciosa", type=int, default=9090, help="porta que não responde")
    args = parser.parse_args()

    try:
        servidor = socket.create_server(("127.0.0.1", args.aberta))
        # backlog=0: cabe só uma conexão pendente. A conexão "ocupante" é feita pelo
        # próprio script e nunca é aceita, então a fila fica cheia permanentemente.
        silenciosa = socket.create_server(("127.0.0.1", args.silenciosa), backlog=0)
        ocupante = socket.create_connection(("127.0.0.1", args.silenciosa))
    except (OSError, OverflowError) as erro:
        raise SystemExit(f"Não foi possível abrir as portas de teste: {erro}")

    print(f"Porta aberta:     127.0.0.1:{args.aberta}")
    print(f"Porta silenciosa: 127.0.0.1:{args.silenciosa} (deve dar timeout)")
    print("Ctrl+C para encerrar.")

    try:
        while True:
            conexao, _ = servidor.accept()
            conexao.close()
    except KeyboardInterrupt:
        print("\nEncerrando.")
    finally:
        ocupante.close()
        silenciosa.close()
        servidor.close()


if __name__ == "__main__":
    main()
