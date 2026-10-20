# SDN DDoS Controller

Controlador SDN desenvolvido em Python utilizando **OS-Ken**, **Mininet** e **Open vSwitch**, com monitoramento de tráfego, detecção estatística global de anomalias e bloqueio temporário de IPs.

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

## 3. Simulando tráfego e detecção

A linha de base global é formada pelas primeiras 5 medições do primeiro IP monitorado. O controlador contabiliza cópias dos pacotes e exclui o sentido de resposta dos fluxos: ICMP Echo Reply é ignorado; TCP usa SYN/SYN-ACK para reconhecer a direção iniciadora; UDP usa a primeira direção observada, pois o protocolo não define universalmente requisições e respostas. Essa regra para UDP é heurística. Nenhum destinatário precisa ser configurado.

Depois da calibração, somente taxas classificadas como normais atualizam o histórico global. Taxas anômalas não entram no cálculo, evitando que tráfego suspeito eleve a referência. O primeiro host deve gerar tráfego normal durante a calibração.

### Tráfego normal

```text
mininet> h1 ping -i 1 h2
```

### Tráfego intenso

```text
mininet> h3 ping -i 0.1 h2
```

Para interromper: `Ctrl+C`.

### Vários hosts ao mesmo tempo

```text
mininet> h1 ping -i 0.1 h2 > /dev/null &
mininet> h3 ping -i 0.1 h2 > /dev/null &
mininet> h4 ping -i 0.1 h2 > /dev/null &
```

Para parar os processos, encerre os comandos de ping ou saia do Mininet.

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

Durante um bloqueio, deve aparecer uma regra semelhante a:

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
| `SDN_DDOS_BASELINE_SAMPLES` | `5` | Amostras do primeiro IP para formar a linha de base global (mín. 2) |
| `SDN_DDOS_HISTORY_SIZE` | `20` | Janela deslizante de amostras normais do histórico global |
| `SDN_DDOS_THRESHOLD_FACTOR` | `3` | Limite estatístico: média + fator × desvio padrão |
| `SDN_DDOS_MIN_RATE_FACTOR` | `1.5` | Taxa também deve superar média × fator |
| `SDN_DDOS_REQUIRED_ANOMALIES` | `2` | Janelas anômalas consecutivas antes de bloquear |
| `SDN_DDOS_BLOCK_TIME` | `30` | Duração do bloqueio em segundos |
| `SDN_DDOS_SUMMARY_EVERY_CYCLES` | `6` | Imprime resumo a cada N ciclos (0 desativa) |
| `SDN_DDOS_LOG_LEVEL` | `INFO` | Nível de log |

Os testes devem ser realizados somente no ambiente controlado do Mininet.
