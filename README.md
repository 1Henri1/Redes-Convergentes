# SDN DDoS Controller

Controlador SDN desenvolvido em Python utilizando **OS-Ken**, **Mininet** e **Open vSwitch**, com monitoramento de tráfego, detecção estatística de anomalias e bloqueio temporário de IPs.

## 1. Instalar dependências

No Debian/Ubuntu:

```bash
sudo apt update
sudo apt install python3 python3-venv mininet openvswitch-switch xterm
```

Criar o ambiente Python:

```bash
python3 -m venv ~/sdn-env
source ~/sdn-env/bin/activate
pip install os-ken
```

## 2. Instalação do projeto

Execute na raiz do projeto.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 3. Executando

### Terminal 1: controlador

```bash
source .venv/bin/activate
python run_controller.py
```

Deve aparecer o banner com os parâmetros. Mantenha esse terminal aberto.

### Terminal 2: rede virtual (Mininet)

O Mininet exige `sudo`. Ele **não** precisa do ambiente virtual.

```bash
sudo mn --topo single,4 \
    --switch ovs,protocols=OpenFlow13 \
    --controller=remote,ip=127.0.0.1,port=6653
```

No terminal do controlador deve aparecer `Switch 1 conectado` e `Datapath 1 registrado`.

### Teste básico (dentro do prompt `mininet>`)

```text
pingall
h1 ping -c 5 h2
```

Execute o `pingall` primeiro: é ele que permite ao controlador aprender o IP de cada host.
Sem isso, o tráfego do host não aparece no monitoramento.

---

## 4. Simulando tráfego e detecção

O controlador forma uma **linha de base** com as primeiras 5 medições de cada host
(a cada 5 s, ou seja, cerca de 25 s) e só depois passa a detectar anomalias.
**Gere tráfego normal por pelo menos 30 s antes do "ataque".**

### Tráfego normal (cria a linha de base)

```text
mininet> h1 ping -i 1 h2 &
```

### Tráfego intenso (dispara o bloqueio)

```text
mininet> h1 ping -i 0.1 h2
```

Para interromper: `Ctrl+C`.

### Vários hosts ao mesmo tempo

```text
mininet> h1 ping -i 0.1 h2 > /dev/null &
mininet> h3 ping -i 0.1 h2 > /dev/null &
mininet> h4 ping -i 0.1 h2 > /dev/null &
```

Para parar todos: `mininet> h1 kill %ping` (repita para h3 e h4) ou saia do Mininet.

\*\*Com `xterm`:

```text
mininet> xterm h1 h3 h4
```

Em cada janela: `ping -i 0.1 h2`.

## 5. Verificar as regras do switch

Em outro terminal:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

Durante um bloqueio, deve aparecer uma regra semelhante a:

```text
priority=100,ip,nw_src=10.0.0.1 actions=drop
```

## 6. Após os testes

Saia do Mininet:

```text
exit
```

E limpe os recursos:

```bash
sudo mn -c
```

## 7. Configuração

Os parâmetros são lidos de variáveis de ambiente com prefixo `SDN_DDOS_`.
Os que não forem definidos usam o padrão.

| Variável                        | Padrão | Descrição                                          |
| ------------------------------- | ------ | -------------------------------------------------- |
| `SDN_DDOS_MONITOR_INTERVAL`     | `5`    | Segundos entre coletas de estatísticas             |
| `SDN_DDOS_BASELINE_SAMPLES`     | `5`    | Amostras para formar a linha de base (mín. 2)      |
| `SDN_DDOS_HISTORY_SIZE`         | `20`   | Janela deslizante de amostras normais (≥ baseline) |
| `SDN_DDOS_THRESHOLD_FACTOR`     | `3`    | Limite = média + fator × desvio padrão             |
| `SDN_DDOS_MIN_RATE_FACTOR`      | `1.5`  | Tráfego também deve superar média × fator (≥ 1)    |
| `SDN_DDOS_REQUIRED_ANOMALIES`   | `2`    | Janelas anômalas consecutivas para bloquear        |
| `SDN_DDOS_BLOCK_TIME`           | `30`   | Duração do bloqueio, em segundos (1 a 65535)       |
| `SDN_DDOS_SUMMARY_EVERY_CYCLES` | `6`    | Imprime resumo a cada N ciclos (0 desativa)        |
| `SDN_DDOS_LOG_LEVEL`            | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`                |

### Fluxo básico

```text
Terminal 1 → python ~/run_controller.py
Terminal 2 → sudo mn ...
Mininet    → pingall
Mininet    → h1 ping -i 0.1 h2
Terminal 3 → ovs-ofctl dump-flows s1
```

Os testes devem ser realizados somente no ambiente controlado do Mininet.
