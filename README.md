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

### Terminal 2: rede virtual (Mininet)

O Mininet exige `sudo`. Ele não precisa do ambiente virtual.

```bash
sudo mn --topo single,4 \
    --switch ovs,protocols=OpenFlow13 \
    --controller=remote,ip=127.0.0.1,port=6653
```

### Teste básico (dentro do prompt `mininet>`)

```text
pingall
h1 ping -c 5 h2
```

Execute `pingall` primeiro para o controlador aprender o IP dos hosts.

---

## 3. Métricas e testes de detecção

 O controlador utiliza duas métricas por par IP origem-destino:
- **PPS:** pacotes por segundo.
- **bytes/s:** volume de dados transmitidos por segundo, calculado a partir dos bytes observados.

Cada métrica tem seu próprio detector estatístico, com baseline global inicializada pelas amostras positivas do primeiro par observado. O limite considera média + fator × desvio padrão, média × fator mínimo e, para PPS, um piso absoluto. A baseline deve ser formada antes da classificação. Taxas anômalas não são adicionadas ao histórico; taxas normais podem atualizar a baseline. Uma origem só é bloqueada quando PPS ou bytes/s apresenta anomalias persistentes pelo número de janelas configurado. O bloqueio é temporário.

**Gerador de tráfego:** `tools/generate_traffic.py` gera tráfego TCP ou UDP para testar o monitoramento de PPS e bytes/s. Embora possa abrir várias conexões ou sockets, o controlador não usa a quantidade de fluxos como métrica de detecção. O tamanho e o intervalo dos envios influenciam o volume observado; os resultados reais dependem do comportamento do sistema e devem ser conferidos nos logs do controlador.

Execute `pingall` antes dos testes para o controlador aprender os hosts. Durante a calibração, gere tráfego normal e aguarde aparecerem os limites globais no log. Os comandos abaixo assumem a topologia `single,4` (h1–h4) e que o repositório está acessível no sistema de arquivos da VM.

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

```text
mininet> h1 ping -i 0.1 h2 > /dev/null &
mininet> h3 ping -i 0.1 h2 > /dev/null &
mininet> h4 ping -i 0.1 h2 > /dev/null &
```

Esse teste aumenta a taxa de pacotes direcionados ao mesmo destino e permite observar PPS, bytes/s e a reação do bloqueio.

### Preparar o servidor de teste

Inicie um servidor TCP em h2. Para testar UDP, troque `--protocol tcp` por `--protocol udp`.

```text
mininet> h2 python3 tools/generate_traffic.py --server --protocol tcp --port 9000 &
```

### Testar PPS e bytes/s com TCP

Em h1, abra 20 conexões TCP, envie blocos de 1200 bytes por 10 segundos e espere 10 ms entre envios de cada conexão:

```text
mininet> h1 python3 tools/generate_traffic.py --dst 10.0.0.2 --protocol tcp --port 9000 --flows 20 --duration 10 --payload-size 1200 --interval 0.01
```

- Para aumentar a intensidade, diminua `--interval` ou aumente `--payload-size`.
- `--flows` controla quantas conexões TCP independentes o gerador tenta abrir; essa quantidade não é usada como métrica pelo detector.
- **Carga leve:** use, por exemplo, `--flows 2 --duration 10 --payload-size 256 --interval 0.1`.

Para testar várias origens simultaneamente, inicie clientes semelhantes em h1, h3 e h4, todos apontando para `10.0.0.2`. Evite iniciar uma carga alta antes da baseline ser formada.

### Testar com UDP

Inicie um servidor UDP em h2:

```text
mininet> h2 python3 tools/generate_traffic.py --server --protocol udp --port 9000 &
```

Em h1, gere tráfego com 20 sockets UDP, cada um enviando blocos de 1200 bytes por 10 segundos:

```text
mininet> h1 python3 tools/generate_traffic.py --dst 10.0.0.2 --protocol udp --port 9000 --flows 20 --duration 10 --payload-size 1200 --interval 0.01
```

UDP não estabelece uma conexão de transporte. O controlador contabiliza os pacotes e bytes por par de IPs; a quantidade de sockets não é usada como métrica de detecção.

Observe no controlador as linhas `[TRÁFEGO/ANÁLISE]`, `[LIMITES GLOBAIS]` e `[MITIGAÇÃO]`. Os resultados dependem da baseline, do intervalo de monitoramento e da taxa realmente observada.

Para parar processos em segundo plano, use `jobs`/`kill` nos hosts ou saia do Mininet.

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
