"""Testes do portscan.py. Rodar com: python3 -m unittest -v"""

import contextlib
import csv
import io
import json
import os
import socket
import tempfile
import unittest
from unittest import mock

import portscan


def porta_livre():
    """Reserva uma porta efêmera e libera em seguida: ninguém fica escutando nela."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestParametros(unittest.TestCase):
    def test_porta_unica_intervalo_e_lista(self):
        self.assertEqual(portscan.parse_portas("80"), [80])
        self.assertEqual(portscan.parse_portas("20-22"), [20, 21, 22])
        self.assertEqual(portscan.parse_portas("22, 80,20-21,80"), [22, 80, 20, 21])
        self.assertEqual(portscan.parse_portas("1,65535"), [1, 65535])

    def test_portas_invalidas(self):
        for texto in ["0", "65536", "abc", "100-50", "1-", "-5", "", "22,,80", "1-2-3"]:
            with self.subTest(texto=texto):
                with self.assertRaises(ValueError):
                    portscan.parse_portas(texto)

    def test_destino(self):
        self.assertEqual(portscan.resolver_destino("127.0.0.1"), "127.0.0.1")
        for destino in ["", "999.1.1.1", "host.invalid"]:
            with self.subTest(destino=destino):
                with self.assertRaises(ValueError):
                    portscan.resolver_destino(destino)

    def test_argumentos_invalidos_encerram_com_codigo_2(self):
        casos = [
            ["127.0.0.1", "-p", "70000"],
            ["127.0.0.1", "-p", "90-80"],
            ["host.invalid", "-p", "80"],
            ["127.0.0.1", "-p", "80", "-t", "0"],
            ["127.0.0.1", "-p", "80", "-o", "saida.txt"],
        ]
        for argv in casos:
            with self.subTest(argv=argv):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
                    portscan.ler_argumentos(argv)
                self.assertEqual(ctx.exception.code, 2)


class TestConexao(unittest.TestCase):
    def verificar(self, ip, porta, esperado, timeout=0.5):
        resultado, _ = portscan.interpretar(portscan.tentar_conexao(ip, porta, timeout))
        self.assertEqual(resultado, esperado)

    def test_porta_aberta(self):
        with socket.create_server(("127.0.0.1", 0)) as servidor:
            self.verificar("127.0.0.1", servidor.getsockname()[1], portscan.ABERTA)

    def test_porta_fechada(self):
        self.verificar("127.0.0.1", porta_livre(), portscan.FECHADA)

    def test_timeout(self):
        # mesma técnica do lab.py: fila cheia faz o kernel ignorar novos SYN (Linux)
        with socket.create_server(("127.0.0.1", 0), backlog=0) as servidor:
            porta = servidor.getsockname()[1]
            with socket.create_connection(("127.0.0.1", porta)):
                self.verificar("127.0.0.1", porta, portscan.TIMEOUT, timeout=0.3)

    def test_erro_de_comunicacao(self):
        # broadcast não é um destino TCP válido: o próprio sistema recusa enviar
        self.verificar("255.255.255.255", 80, portscan.ERRO)

    def test_interpretar(self):
        self.assertEqual(portscan.interpretar(None)[0], portscan.ABERTA)
        self.assertEqual(portscan.interpretar(ConnectionRefusedError())[0], portscan.FECHADA)
        self.assertEqual(portscan.interpretar(socket.timeout())[0], portscan.TIMEOUT)
        self.assertEqual(portscan.interpretar(OSError(113, "No route to host")),
                         (portscan.ERRO, "No route to host"))


class TestPrograma(unittest.TestCase):
    def rodar(self, argv):
        with contextlib.redirect_stdout(io.StringIO()) as saida:
            codigo = portscan.main(argv)
        return codigo, saida.getvalue()

    def test_exporta_csv_e_json(self):
        with socket.create_server(("127.0.0.1", 0)) as servidor, tempfile.TemporaryDirectory() as pasta:
            aberta, fechada = servidor.getsockname()[1], porta_livre()
            portas = f"{aberta},{fechada}"

            caminho_csv = os.path.join(pasta, "r.csv")
            codigo, _ = self.rodar(["127.0.0.1", "-p", portas, "-t", "0.5", "-o", caminho_csv])
            self.assertEqual(codigo, 0)
            with open(caminho_csv, encoding="utf-8") as f:
                linhas = list(csv.DictReader(f))
            self.assertEqual([(int(l["porta"]), l["resultado"]) for l in linhas],
                             [(aberta, "aberta"), (fechada, "fechada")])

            caminho_json = os.path.join(pasta, "r.json")
            codigo, _ = self.rodar(["127.0.0.1", "-p", portas, "-t", "0.5", "-o", caminho_json])
            self.assertEqual(codigo, 0)
            with open(caminho_json, encoding="utf-8") as f:
                dados = json.load(f)
            self.assertFalse(dados["interrompido"])
            self.assertEqual([r["resultado"] for r in dados["resultados"]], ["aberta", "fechada"])

    def test_ctrl_c_mostra_resultados_parciais(self):
        # a 1ª tentativa é recusada; na 2ª o usuário aperta Ctrl+C
        chamadas = []

        def falsa_conexao(ip, porta, timeout):
            chamadas.append(porta)
            if len(chamadas) == 2:
                raise KeyboardInterrupt
            return ConnectionRefusedError()

        with mock.patch.object(portscan, "tentar_conexao", side_effect=falsa_conexao):
            codigo, saida = self.rodar(["127.0.0.1", "-p", "1-5"])
        self.assertEqual(codigo, 130)
        self.assertIn("1 de 5 portas testadas", saida)

    def test_falha_ao_salvar_nao_quebra(self):
        with contextlib.redirect_stderr(io.StringIO()) as erros:
            codigo, saida = self.rodar(["127.0.0.1", "-p", str(porta_livre()),
                                        "-o", "/pasta/que/nao/existe/r.json"])
        self.assertEqual(codigo, 1)
        self.assertIn("Resumo:", saida)
        self.assertIn("Erro ao salvar", erros.getvalue())


if __name__ == "__main__":
    unittest.main()
