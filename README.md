# SDN DDoS Controller

Controlador SDN desenvolvido em Python utilizando **OS-Ken**, **Mininet** e **Open vSwitch**, com monitoramento de tráfego, detecção estatística por conexão e por destino usando PPS e bytes/s, análise complementar de entropia e bloqueio temporário das origens identificadas.

## 1. Instalar dependências

No Debian/Ubuntu:

```bash
sudo apt update
sudo apt install python3 python3-venv mininet openvswitch-switch xterm
```

Criar o ambiente Python:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 2. Executando

### Terminal 1: controlador

```bash
source .venv/bin/activate
python run_controller.py
```

Deve aparecer o banner com os parâmetros. Mantenha esse terminal aberto.

### Terminal 2: rede virtual com parâmetros realistas

Use o novo iniciador de rede. Ele aplica largura de banda, atraso, jitter e fila limitada com `TCLink`; o controlador deve estar rodando no terminal 1.

```bash
sudo python3 tools/run_mininet.py
```

Parâmetros padrão por enlace: **10 Mbps**, **20 µs de atraso**, **0 µs de jitter**, fila de **100 pacotes** e **0% de perda artificial**. O caminho h1→h4 e a resposta atravessam quatro enlaces no total, portanto o atraso configurado contribui com cerca de **0,5 ms (500 µs) de RTT teórico**. O RTT real medido pode ser maior por causa do processamento do Linux, Mininet, Open vSwitch e controlador; esse valor é um alvo de configuração, não uma garantia.

O script **não inicia pings automáticos** nem executa `pingall`. No prompt `mininet>`, envie manualmente, por exemplo:

```text
h1 ping -c 10 h4
```

As métricas dos pings manuais observados pelo switch são acumuladas durante o período e aparecem no relatório periódico: enviados, recebidos, perdidos e RTT (último e médio). Os contadores são zerados após cada relatório. Uma solicitação sem resposta é contabilizada como perdida após pelo menos 2 segundos, na próxima coleta do controlador. Essa medição é feita no controlador e pode incluir sobrecarga de processamento, portanto o RTT exibido pelo próprio comando `ping` é a referência de latência fim a fim. Para alterar os parâmetros:

```bash
sudo python3 tools/run_mininet.py --bw 10 --delay 20us --jitter 0us --queue 100 --loss 0
```

`--loss` adiciona perda artificial; mantenha em `0` para medir perdas causadas por congestionamento. O controlador deixa de exibir um par origem-destino quando ele registra **zero pacotes em duas coletas consecutivas**. Com o intervalo padrão de 5 segundos, isso corresponde a aproximadamente 10 segundos sem pacotes; quando o tráfego voltar, o par reaparece após uma nova coleta inicial.

No primeiro terminal, o controlador deixa de exibir um par origem-destino quando ele registra **zero pacotes em duas coletas consecutivas**. Com o intervalo padrão de 5 segundos, isso corresponde a aproximadamente 10 segundos sem pacotes; quando o tráfego voltar, o par reaparece após uma nova coleta inicial.

### Teste básico (dentro do prompt `mininet>`)

```text
h1 ping -c 5 h2
```

Não há tráfego de teste automático. O primeiro ping manual também permite ao switch aprender os endereços MAC/IP necessários.

---

## 3. Métricas e testes de detecção

O controlador separa a frequência de avaliação da frequência de impressão no terminal. Por padrão, avalia as métricas a cada **2 segundos** e imprime um relatório consolidado a cada **10 segundos**. Assim, cinco avaliações acontecem entre relatórios. A detecção, a confirmação de anomalias e a aplicação/expiração de bloqueios continuam ocorrendo em cada ciclo de avaliação; somente a apresentação no terminal é agrupada. Eventos e métricas observados no período são exibidos no relatório seguinte.\n\nO controlador utiliza duas métricas por par IP origem-destino:
- **PPS:** pacotes por segundo.
- **bytes/s:** volume de dados transmitidos por segundo, calculado a partir dos bytes observados.

A detecção opera em dois níveis complementares. **Por conexão**, cada origem é comparada com as demais origens do mesmo destino, separadamente para PPS e bytes/s. A média e o desvio padrão usam as referências normais das outras conexões, excluindo a origem avaliada. São necessárias pelo menos três conexões de referência; antes disso, as taxas contribuem para formar a referência. Conexões ausentes por dois ciclos são removidas da população de referência. Amostras anômalas não atualizam essa referência. **Por destino**, PPS agregado e bytes/s agregado mantêm baselines temporais independentes para detectar elevações coordenadas. O limite de PPS considera média + 3 × desvio padrão, média × fator mínimo e o piso absoluto configurável. Para bytes/s, o limite é `max(média + 3 × desvio padrão, média × 1,5)`, sem piso absoluto. Assim, uma rede habituada a 10.000 bytes/s pode sinalizar uma elevação persistente para 20.000 bytes/s mesmo que o PPS não aumente. A anomalia precisa persistir pelo número configurado de janelas consecutivas. Cada destino possui uma baseline conjunta e independente, com uma amostra por janela. Quando uma solicitação de comunicação chega para um destino ainda sem detector e cuja média de recebimento é, portanto, zero, o controlador cria uma baseline individual para ele. A baseline é preenchida de forma conjunta ao longo de `baseline_samples` ciclos reais de monitoramento. Em cada ciclo, PPS agregado, bytes/s agregado e entropia são coletados para o mesmo destino; o progresso aparece em uma única mensagem `[BASELINE] Destino ... Amostra k/n`. A análise agregada do destino só passa à detecção após completar esses ciclos; a análise por conexão começa assim que há três referências normais disponíveis. As métricas não exibem contadores de baseline separados. São consideradas solicitações TCP SYN, datagramas UDP e ICMP Echo Request. O limite é o maior entre média + 3 × desvio padrão, média × fator mínimo e o piso absoluto configurável. Amostras acima do limite não entram no histórico; amostras normais atualizam a janela. A anomalia precisa persistir pelo número configurado de janelas consecutivas.

A implementação também calcula a **entropia de Shannon das origens** em cada destino. Para cada janela, a proporção de pacotes da origem i é `p_i = P_i / Σ_j P_j`, e a entropia é `H = -Σ_i p_i log₂(p_i)`. A saída mostra a entropia normalizada entre 0 e 1, o número de origens e o limite estatístico de H. A baseline é específica de cada destino e não é atualizada quando há anomalia agregada ou individual de PPS/bytes/s, nem quando a própria entropia está elevada. A entropia é um indicador complementar de distribuição, mas não bloqueia origens sozinha, pois não identifica qual emissor é responsável.

A mitigação bloqueia somente origens cuja própria conexão apresente anomalia persistente de PPS ou bytes/s em relação às demais conexões do destino. Assim, origens já ativas também podem ser identificadas, e uma conexão nova não contamina a referência antes de ser avaliada. As elevações agregadas e a entropia continuam sinalizando eventos, mas **não provocam o bloqueio indiscriminado de todas as origens**: sem uma origem individualmente identificada, o controlador registra que não houve atribuição. As origens confirmadas são bloqueadas temporariamente em envio e recebimento.

Exemplo ilustrativo das mensagens durante uma anomalia. PPS, bytes/s e entropia são apresentados juntos na linha do destino; a lista de IPs bloqueados é exibida em todos os ciclos, mesmo vazia:

```text
[CONEXÃO] 10.0.0.3 -> 10.0.0.10 | PPS 30.00 (média 10.00 | desvio 0.00 | limite 15.00 | ANOMALIA 1/2) | bytes/s 300.00 (média 100.00 | desvio 0.00 | limite 150.00 | ANOMALIA 1/2)
[DESTINO] 10.0.0.10 | PPS: 145.00 (média 30.00 | desvio 5.00 | limite 45.00 | ANOMALIA 1/2) | bytes/s: 8120.00 | origens: 6 | H: 2.400 bits (norm. 0.930) | H média 0.500 | H desvio 0.250 | H limite 1.250 | ENTROPIA ELEVADA
[IPS BLOQUEADOS] Origens (envio): 10.0.0.3 | Destinos (recebimento): 10.0.0.3
[CLASSIFICAÇÃO] Destino: 10.0.0.10 | PADRÃO DISTRIBUÍDO (possível DDoS) | origens: 6 | entropia: 2.400 bits | normalizada: 0.930
[ATRIBUIÇÃO] Destino: 10.0.0.10 | gatilho: PPS E/OU BYTES/S POR CONEXÃO | origens identificadas: 10.0.0.3
[BLOQUEIO ATIVADO] IP 10.0.0.3 bloqueado para ENVIAR e RECEBER por 30s (prioridade OpenFlow 100).
```

Os números acima são apenas um exemplo de formatação, não resultados medidos.

PPS e bytes/s são avaliados individualmente por conexão e também de forma agregada por destino. A análise por conexão identifica emissores que destoam dos demais; a análise agregada identifica aumentos simultâneos de várias origens. A entropia caracteriza mudanças na distribuição das origens, como indicador complementar. A entropia elevada, desde que envolva o número mínimo de origens e supere o limite estatístico, classifica o padrão como possível DDoS e pode iniciar o bloqueio sem anomalia de PPS.

**Gerador de tráfego:** `tools/generate_traffic.py` gera tráfego TCP ou UDP para testar o monitoramento de PPS e bytes/s. Embora possa abrir várias conexões ou sockets, o controlador não usa a quantidade de fluxos como métrica de detecção. O tamanho e o intervalo dos envios influenciam o volume observado; os resultados reais dependem do comportamento do sistema e devem ser conferidos nos logs do controlador.

Inicie os testes com um ping manual para o controlador aprender os hosts. Durante a calibração, mantenha tráfego normal e aguarde a formação da baseline individual de cada destino e a exibição de seus limites no log. Os comandos abaixo assumem a topologia `single,4` (h1–h4) e que o repositório está acessível no sistema de arquivos da VM.


### Cenário automático de pings (editável por métodos)

O cenário automático é opcional. Primeiro, edite diretamente o método `main()` em `tools/ping_scenario.py`. A sequência inicial já contém dois blocos:

1. `normal`: h1 e h2 enviam até 100 pings cada para h10, com intervalo de 1 segundo e payload de 56 bytes.
2. `sobrecarga`: h3, h4, h5 e h6 enviam até 500 pings cada para h10, com intervalo de 100 ms e payload de 56 bytes, enquanto o primeiro grupo continua ativo.

Para executar a sequência, inicie o controlador no terminal 1 e rode no terminal 2:

```bash
sudo python3 tools/run_mininet.py --auto-ping-test
```

A CLI do Mininet continua disponível enquanto o cenário roda em segundo plano. Os processos são encerrados ao final da sequência ou quando a rede é fechada.

#### Como editar o cenário

Abra `tools/ping_scenario.py` e modifique somente o método `main()` para organizar as etapas. Os métodos disponíveis são:

- `start_pings(group, sources, destination, interval, count, packet_size)`: inicia pings simultâneos para cada host de `sources`. `interval` define o intervalo em segundos (`-i`), `count` define o máximo de pacotes por origem (`-c`) e `packet_size` define o tamanho do payload em bytes (`-s`).
- `wait(seconds)`: aguarda o tempo indicado. Os grupos já iniciados continuam enviando durante a pausa.
- `stop_pings(group)`: encerra apenas o grupo indicado.
- `stop_all()`: encerra todos os grupos ativos.

Exemplo de sequência com três blocos:

```python
def main(self):
    self.start_pings(
        "normal", ["h1", "h2"], "h10",
        interval=1.0, count=100, packet_size=56
    )
    self.wait(35)

    self.start_pings(
        "sobrecarga_1", ["h3", "h4"], "h10",
        interval=0.1, count=500, packet_size=128
    )
    self.wait(20)

    self.start_pings(
        "sobrecarga_2", ["h5", "h6", "h7"], "h10",
        interval=0.05, count=1000, packet_size=256
    )
    self.wait(30)

    self.stop_pings("sobrecarga_2")
    self.wait(10)  # o grupo normal e sobrecarga_1 continuam ativos

    self.stop_all()
```

Para acrescentar máquinas, basta incluir seus nomes nas listas, desde que existam na topologia. Para criar outra etapa, adicione outra chamada a `start_pings()`. Uma pausa com `wait()` não interrompe os grupos anteriores. Use nomes de grupo diferentes para cada conjunto que deseja controlar separadamente. Os três parâmetros do ping são configurados diretamente em cada chamada: `interval` (`-i`), `count` (`-c`, quantidade máxima por host) e `packet_size` (`-s`, tamanho do payload em bytes). Se `wait()` ou `stop_pings()` encerrar o grupo antes, os processos são interrompidos mesmo que não tenham enviado toda a quantidade configurada. O tamanho passado a `-s` é o payload ICMP, não o tamanho total do quadro Ethernet.

O iniciador usa apenas `--auto-ping-test`; os parâmetros do experimento ficam no próprio arquivo Python, evitando precisar alterar a linha de comando a cada teste. Sem essa opção, nenhum ping automático é iniciado.

**Observação:** este cenário gera tráfego ICMP de teste somente na topologia Mininet local. A taxa observada depende da largura de banda, das filas e da capacidade da VM. Se a rede saturar antes da formação da baseline, aumente a largura de banda ou reduza a intensidade do teste.

### Tráfego normal

```text
mininet> h1 ping -i 1 h2
```

### Tráfego intenso

```text
mininet> h3 ping -i 0.1 h2
```

Para interromper: `Ctrl+C`.

### Vários hosts ao mesmo tempo: testar PPS e bytes/s

Com `xterm`:

```text
mininet> xterm h1 h3 h4
```

Em cada janela, execute o tráfego desejado, por exemplo `ping -i 0.1 h2`.

## 4. Verificar as regras do switch

Em outro terminal:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

Durante um bloqueio, deve aparecer uma regra semelhante a. O IP de origem é bloqueado para todos os destinos:

```text
priority=100,ip,nw_src=10.0.0.1 actions=drop
```

## 5. Após os testes

Saia do Mininet:

```text
exit
```

E limpe os recursos:

```bash
sudo mn -c
```

### Expiração de destinos inativos

Um destino é removido do monitoramento quando apresenta **0 PPS em dois ciclos consecutivos de avaliação**. Nessa remoção, o controlador descarta as baselines de PPS e entropia, o histórico de anomalias e os candidatos associados. Um único ciclo com 0 PPS não remove o destino: se houver tráfego no ciclo seguinte, o contador de inatividade volta a zero.

Quando uma nova solicitação de comunicação for observada para esse destino (TCP SYN inicial, UDP ou ICMP Echo Request), o controlador cria uma nova baseline. As cinco amostras são coletadas novamente, uma por ciclo de avaliação, antes de iniciar a detecção.

## 6. Configuração

Os parâmetros são lidos de variáveis de ambiente com prefixo `SDN_DDOS_`. Os que não forem definidos usam o padrão. `SDN_DDOS_MONITOR_INTERVAL` controla a frequência de avaliação; `SDN_DDOS_REPORT_INTERVAL` controla a frequência de impressão.

| Variável | Padrão | Descrição |
| --- | ---: | --- |
| `SDN_DDOS_MONITOR_INTERVAL` | `5` | Segundos entre coletas e avaliações das métricas |
| `SDN_DDOS_REPORT_INTERVAL` | `10` | Segundos entre relatórios consolidados no terminal |
| `SDN_DDOS_BASELINE_SAMPLES` | `5` | Amostras por destino para formar a linha de base estatística (mín. 2) |
| `SDN_DDOS_HISTORY_SIZE` | `20` | Janela deslizante de amostras normais do histórico estatístico |
| `SDN_DDOS_THRESHOLD_FACTOR` | `3` | Limite estatístico: média + fator × desvio padrão |
| `SDN_DDOS_MIN_RATE_FACTOR` | `1.5` | Taxa também deve superar média × fator |
| `SDN_DDOS_MINIMUM_PPS` | `10.0` | Piso absoluto do limite de PPS, agregado e por conexão (não aplicado a bytes/s) |
| `SDN_DDOS_ENTROPY_THRESHOLD_FACTOR` | `3.0` | Fator de desvio padrão para o limite de entropia |
| `SDN_DDOS_MINIMUM_ENTROPY_FACTOR` | `1.5` | Fator mínimo multiplicativo aplicado à média da entropia |
| `SDN_DDOS_MINIMUM_DISTRIBUTED_SOURCES` | `2` | Número mínimo de origens para caracterizar distribuição elevada |
| `SDN_DDOS_REQUIRED_ANOMALIES` | `2` | Janelas anômalas consecutivas de PPS ou entropia antes de bloquear |
| `SDN_DDOS_BLOCK_TIME` | `30` | Duração do bloqueio em segundos |
| `SDN_DDOS_LOG_LEVEL` | `INFO` | Nível de log |

Os testes devem ser realizados somente no ambiente controlado do Mininet. Para executar os testes unitários, instale `pytest` no ambiente virtual (`pip install pytest`) e execute `pytest -q tests`. Os testes cobrem as baselines agregadas e por conexão, detecção de anomalias individuais e coordenadas, entropia e exclusão de amostras anômalas.
