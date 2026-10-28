# SDN DDoS Controller

Controlador SDN desenvolvido em Python utilizando **OS-Ken**, **Mininet** e **Open vSwitch**, com monitoramento de tráfego, detecção estatística por par IP origem-destino e bloqueio temporário de IPs.

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

Parâmetros padrão por enlace: **10 Mbps**, **20 µs de atraso**, **0 µs de jitter**, fila de **100 pacotes** e **0% de perda artificial**. O caminho h1→h4 e a resposta atravessam quatro enlaces no total, portanto o atraso configurado contribui com cerca de **0,08 ms (80 µs) de RTT teórico**. O RTT real medido pode ser maior por causa do processamento do Linux, Mininet, Open vSwitch e controlador; esse valor é um alvo de configuração, não uma garantia.

O script **não inicia pings automáticos** nem executa `pingall`. No prompt `mininet>`, envie manualmente, por exemplo:

```text
h1 ping -c 10 h4
```

A cada **5 segundos**, o primeiro terminal (controlador) apresenta um resumo dos pings observados nesse intervalo: total de pacotes enviados, recebidos e perdidos, além do RTT observado e médio das respostas recebidas. Os contadores são zerados após cada resumo, então cada linha representa somente o intervalo correspondente. Uma solicitação sem resposta é contabilizada como perdida após pelo menos 2 segundos, na próxima coleta do controlador. Essa medição é feita no controlador e pode incluir sobrecarga de processamento, portanto o RTT exibido pelo próprio comando `ping` é a referência de latência fim a fim. Para alterar os parâmetros:

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

O controlador utiliza duas métricas por par IP origem-destino:
- **PPS:** pacotes por segundo.
- **bytes/s:** volume de dados transmitidos por segundo, calculado a partir dos bytes observados.

Cada métrica tem seu próprio detector estatístico, com baseline global inicializada pelas amostras positivas do primeiro par observado. O limite considera média + fator × desvio padrão, média × fator mínimo e, para PPS, um piso absoluto. A baseline deve ser formada antes da classificação. Taxas anômalas não são adicionadas ao histórico; taxas normais podem atualizar a baseline. Uma origem só é bloqueada quando PPS ou bytes/s apresenta anomalias persistentes pelo número de janelas configurado. O bloqueio é temporário.

**Gerador de tráfego:** `tools/generate_traffic.py` gera tráfego TCP ou UDP para testar o monitoramento de PPS e bytes/s. Embora possa abrir várias conexões ou sockets, o controlador não usa a quantidade de fluxos como métrica de detecção. O tamanho e o intervalo dos envios influenciam o volume observado; os resultados reais dependem do comportamento do sistema e devem ser conferidos nos logs do controlador.

Inicie os testes com um ping manual para o controlador aprender os hosts. Durante a calibração, gere tráfego normal e aguarde aparecerem os limites globais no log. Os comandos abaixo assumem a topologia `single,4` (h1–h4) e que o repositório está acessível no sistema de arquivos da VM.

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

## 6. Configuração

Os parâmetros são lidos de variáveis de ambiente com prefixo `SDN_DDOS_`. Os que não forem definidos usam o padrão.

| Variável | Padrão | Descrição |
| --- | ---: | --- |
| `SDN_DDOS_MONITOR_INTERVAL` | `5` | Segundos entre coletas de estatísticas |
| `SDN_DDOS_BASELINE_SAMPLES` | `5` | Amostras do primeiro par origem-destino para formar a linha de base estatística (mín. 2) |
| `SDN_DDOS_HISTORY_SIZE` | `20` | Janela deslizante de amostras normais do histórico estatístico |
| `SDN_DDOS_THRESHOLD_FACTOR` | `3` | Limite estatístico: média + fator × desvio padrão |
| `SDN_DDOS_MIN_RATE_FACTOR` | `1.5` | Taxa também deve superar média × fator |
| `SDN_DDOS_MINIMUM_PPS` | `2.0` | Piso absoluto do limite para evitar alertas quando a média é próxima de zero |
| `SDN_DDOS_REQUIRED_ANOMALIES` | `2` | Janelas anômalas consecutivas antes de bloquear |
| `SDN_DDOS_BLOCK_TIME` | `30` | Duração do bloqueio em segundos |
| `SDN_DDOS_SUMMARY_EVERY_CYCLES` | `6` | Imprime resumo a cada N ciclos (0 desativa) |
| `SDN_DDOS_LOG_LEVEL` | `INFO` | Nível de log |

Os testes devem ser realizados somente no ambiente controlado do Mininet.
