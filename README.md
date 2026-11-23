# Port Scanner TCP

Scanner de portas TCP em Python, feito para o Roteiro 4 de Tecnologias Hacker (Insper).
Ele tenta abrir uma conexão TCP com cada porta e diz se ela está **aberta**, **fechada**,
se deu **timeout** ou se aconteceu algum outro **erro**.

> Use só em máquinas suas ou em que você tenha autorização para testar.

## Requisitos

- Python 3.8 ou mais novo
- Nada para instalar: usa só a biblioteca padrão (`socket`, `argparse`, `csv`, `json`, `time`)
- Nmap (opcional), só para comparar os resultados

## Como rodar

```bash
python3 portscan.py <destino> -p <portas> [opções]
```

| Parâmetro | O que faz |
|---|---|
| `destino` | IP (IPv4) ou hostname do alvo |
| `-p`, `--portas` | Porta (`80`), intervalo (`20-25`) ou lista (`22,80,8000-8010`). Obrigatório |
| `-t`, `--timeout` | Tempo limite de cada tentativa, em segundos (padrão `1.0`, máximo `60`) |
| `-o`, `--saida` | Salva os resultados em um arquivo `.csv` ou `.json` |
| `-a`, `--abertas` | Mostra na tela só as portas abertas (o resumo e o arquivo continuam completos) |
| `-h`, `--help` | Mostra a ajuda |

## Exemplos

```bash
python3 portscan.py localhost -p 8080                 # uma porta
python3 portscan.py 127.0.0.1 -p 1-1024 -a            # intervalo, só as abertas
python3 portscan.py localhost -p 22,80,8000-8010 -t 0.5
python3 portscan.py localhost -p 1-1024 -o resultado.json
```

Saída:

```
Destino: localhost (127.0.0.1)
Portas: 5 | Timeout: 1.0s | Início: 2026-11-20 10:55:10

DESTINO          PORTA  RESULTADO  SERVIÇO (palpite)  DETALHE
localhost         5432  aberta     postgresql         conexão estabelecida
localhost         7000  fechada    afs3-fileserver    conexão recusada
localhost         8000  aberta     irdmi              conexão estabelecida
localhost         8080  aberta     http-alt           conexão estabelecida
localhost         9090  timeout    websm              sem resposta no tempo limite

Resumo: 3 aberta(s), 1 fechada(s), 1 timeout, 0 erro | tempo total: 1.01s
Portas abertas: 5432, 8000, 8080
```

## O que cada resultado quer dizer

- **aberta**: o handshake TCP completou, ou seja, tem algum serviço escutando na porta.
- **fechada**: o destino respondeu recusando a conexão (RST). Não tem nada escutando ali.
- **timeout**: nenhuma resposta dentro do tempo limite. Pode ser firewall descartando pacotes,
  host desligado ou rede lenta, e só com isso não dá para saber qual. Por isso não é tratado como fechada.
- **erro**: outro problema impediu a tentativa (por exemplo, rede inalcançável).

Entradas inválidas (porta fora de 1-65535, intervalo invertido, destino que não resolve, timeout ≤ 0)
são recusadas antes de começar, com uma mensagem explicando o problema. Ctrl+C interrompe a varredura
e mostra o que já foi testado.

Códigos de saída: `0` ok, `1` falha ao salvar o arquivo, `2` parâmetro inválido, `130` interrompido.

## Melhoria implementada: exportação dos resultados

Com `-o`, o resultado é salvo em arquivo para ser consultado ou comparado depois:

- **CSV**: uma linha por porta (`destino, ip, porta, resultado, servico, detalhe`), abre direto em planilha.
- **JSON**: os mesmos dados, mais o timeout usado, data, duração e se a varredura foi interrompida.

Se a varredura for interrompida com Ctrl+C, o arquivo é salvo com o que foi testado até ali.
Exemplos prontos em [evidencias/resultado.csv](evidencias/resultado.csv) e
[evidencias/resultado.json](evidencias/resultado.json).

Também mostro o tempo total da varredura e o nome de serviço normalmente associado à porta
(tirado da tabela do sistema, via `socket.getservbyport`). Esse nome é só um palpite: a porta 8000,
por exemplo, aparece como `irdmi`, mas no teste quem estava ali era um servidor HTTP.

## Ambiente de teste

Para testar sem depender de outras máquinas, o `lab.py` sobe duas portas locais:

```bash
python3 lab.py                         # 8080 aceita conexões, 9090 não responde (timeout)
python3 -m http.server 8000            # um serviço real para ligar e desligar
python3 portscan.py localhost -p 7000,8000,8080,9090
nmap -sT -p 7000,8000,8080,9090 localhost   # para comparar
```

A porta 9090 do `lab.py` fica com a fila de conexões cheia de propósito, então o kernel descarta
novos pedidos de conexão sem responder. É o jeito de reproduzir um timeout localmente, sem firewall
e sem root (testado no Linux).

## Testes

```bash
python3 -m unittest -v
```

Os testes cobrem a validação dos parâmetros, os quatro resultados possíveis (com sockets reais),
a exportação, o Ctrl+C e a falha ao salvar o arquivo.

## Arquivos

- `portscan.py`: o scanner
- `lab.py`: ambiente de teste local
- `test_portscan.py`: testes automatizados
- `evidencias/`: saídas dos testes, da comparação com o Nmap e do experimento de mudança de estado
- `relatorio.docx`: relatório técnico
