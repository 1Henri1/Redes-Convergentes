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

O controlador calcula três métricas:
- **PPS:** pacotes por segundo para cada par origem-destino.
- **bytes/s:** volume de dados por segundo para cada par origem-destino.
- **Fluxos novos/s:** novos fluxos iniciados por segundo, agregados por destino. TCP é contado pelo SYN inicial; UDP, pela tupla de protocolo/IPs/portas; ICMP Echo Request repetido com o mesmo identificador é tratado como o mesmo fluxo durante o período de expiração.

Cada detector usa uma baseline estatística e um limite baseado em média + fator × desvio padrão, com um limite mínimo adicional. A baseline precisa ser formada antes que o detector classifique anomalias. Para PPS e bytes/s, a baseline é construída com taxas positivas do primeiro par observado. Para fluxos novos/s, janelas sem novos fluxos também entram na baseline, pois representam comportamento normal. Taxas anômalas não atualizam o histórico. O detector de fluxos novos usa uma janela anômala para acionar mitigação: se muitos fluxos novos forem direcionados ao mesmo destino, bloqueia as origens que contribuíram para a rajada. Os bloqueios são temporários.

**Importante:** `ping` é adequado para testar PPS e bytes/s, mas não é um bom teste de criação de muitos fluxos, pois pings repetidos normalmente reutilizam o mesmo identificador ICMP. Para testar fluxos novos, use conexões TCP distintas, por exemplo com `iperf3` e múltiplos fluxos paralelos.

Execute `pingall` antes dos testes para o controlador aprender os hosts. Durante a calibração, gere tráfego normal e aguarde aparecerem os limites globais no log.

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

Esse teste aumenta a taxa de pacotes direcionados ao mesmo destino e permite observar PPS, bytes/s e a reação do bloqueio. Não garante, por si só, que haverá muitos fluxos novos.

### Testar novos fluxos TCP por segundo

Instale o `iperf3` no sistema Debian/Ubuntu usado pela VM, se necessário:

```bash
sudo apt install iperf3
```

No prompt do Mininet, inicie o servidor no destino:

```text
mininet> h2 iperf3 -s &
```

Gere múltiplas conexões TCP simultâneas a partir de um host:

```text
mininet> h1 iperf3 -c 10.0.0.2 -P 20 -t 10
```

Para simular uma rajada distribuída, execute comandos semelhantes a partir de outros hosts, direcionando-os para `10.0.0.2`:

```text
mininet> h3 iperf3 -c 10.0.0.2 -P 20 -t 10
mininet> h4 iperf3 -c 10.0.0.2 -P 20 -t 10
```

Observe no controlador as linhas `[FLUXOS NOVOS/ANÁLISE]`, `[LIMITES GLOBAIS] fluxos novos/s` e `[MITIGAÇÃO]`. Se a taxa ultrapassar o limite estatístico, as origens que contribuíram para a rajada devem ser bloqueadas. O resultado depende da baseline, do intervalo de monitoramento e da taxa efetivamente observada.

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
