# SDN DDoS Controller

Controlador SDN desenvolvido em Python utilizando **OS-Ken**, **Mininet** e **Open vSwitch**, com monitoramento de tráfego, detecção estatística de anomalias e bloqueio temporário de IPs.

## 1. Instalar dependências

No Debian/Ubuntu:

```bash
sudo apt update
sudo apt install mininet openvswitch-switch python3-venv
```

Criar o ambiente Python:

```bash
python3 -m venv ~/sdn-env
source ~/sdn-env/bin/activate
pip install os-ken
```

## 2. Iniciar o controlador

Ative o ambiente virtual:

```bash
source ~/sdn-env/bin/activate
```

Execute:

```bash
python ~/run_controller.py
```

Mantenha esse terminal aberto.

## 3. Iniciar o Mininet

Abra outro terminal e execute:

```bash
sudo mn --topo single,4 \
    --switch ovs,protocols=OpenFlow13 \
    --controller=remote,ip=127.0.0.1,port=6653
```

## 4. Testar a rede

Dentro do Mininet:

```text
pingall
```

Para testar dois hosts:

```text
h1 ping -c 5 h2
```

Para gerar tráfego contínuo:

```text
h1 ping -i 0.1 h2
```

Ou uma quantidade limitada:

```text
h1 ping -i 0.1 -c 1000 h2
```

### Executar múltiplos tráfegos simultaneamente

Para gerar tráfego de vários hosts ao mesmo tempo, pode-se utilizar o `xterm`.

Primeiro, instale:

```bash
sudo apt install xterm
```

Dentro do Mininet, abra um terminal para cada host:

```text
xterm h1
xterm h3
xterm h4
```

Cada comando abrirá uma janela de terminal correspondente ao host.

Por exemplo, em cada janela:

**h1:**

```bash
ping -i 0.1 h2
```

**h3:**

```bash
ping -i 0.1 h2
```

**h4:**

```bash
ping -i 0.1 h2
```

Assim, os três hosts podem gerar tráfego simultaneamente para `h2`, permitindo testar o monitoramento e a detecção de anomalias do controlador.

Para fechar uma instância do `xterm`, utilize:

```text
Ctrl+C
```

ou simplesmente feche a janela.

## 5. Verificar as regras do switch

Em outro terminal:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

Durante um bloqueio, deve aparecer uma regra semelhante a:

```text
priority=100,...ipv4_src=10.0.0.1,...actions=drop
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

### Fluxo básico

```text
Terminal 1 → python ~/run_controller.py
Terminal 2 → sudo mn ...
Mininet    → pingall
Mininet    → h1 ping -i 0.1 h2
Terminal 3 → ovs-ofctl dump-flows s1
```

Os testes devem ser realizados somente no ambiente controlado do Mininet.
