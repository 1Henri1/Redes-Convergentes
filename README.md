# SDN DDoS Controller

Controlador SDN desenvolvido em Python utilizando **OS-Ken**, **Mininet** e **Open vSwitch**, com monitoramento de tráfego, detecção estatística de PPS agregado por destino e bloqueio temporário das origens identificadas.

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

A cada **5 segundos**, as métricas dos pings manuais observados pelo switch aparecem na própria linha `[TRÁFEGO/ANÁLISE]` do respectivo par origem-destino: enviados, recebidos, perdidos e RTT (último e médio). Os contadores são zerados após cada intervalo. Uma solicitação sem resposta é contabilizada como perdida após pelo menos 2 segundos, na próxima coleta do controlador. Essa medição é feita no controlador e pode incluir sobrecarga de processamento, portanto o RTT exibido pelo próprio comando `ping` é a referência de latência fim a fim. Para alterar os parâmetros:

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

A detecção principal de DDoS utiliza o **PPS agregado recebido por cada destino**. Cada IP de servidor possui uma baseline independente, formada por uma amostra por janela de monitoramento. O limite é calculado por destino como o maior valor entre média + 3 × desvio padrão, média × fator mínimo e o piso absoluto configurável. Os dois últimos critérios evitam alertas causados por pequenas oscilações quando o desvio padrão é zero ou muito baixo. Amostras anômalas não entram no histórico; amostras normais atualizam a janela. O controlador só considera a anomalia confirmada após o número configurado de janelas consecutivas. É necessário iniciar o controlador e aprender os IPs dos servidores antes do ataque, mantendo um período inicial de tráfego benigno para formar as baselines.

Quando um destino apresenta anomalia persistente, o controlador identifica os pares origem-destino que começaram a contribuir na janela em que a anomalia surgiu e bloqueia somente essas origens. Assim, hosts que já enviavam tráfego de forma estável antes do aumento não são bloqueados apenas por terem PPS elevado. O bloqueio continua sendo aplicado ao IP de origem e é temporário. **Limitação:** se um cliente legítimo novo começar a enviar tráfego exatamente durante o mesmo evento, apenas PPS não permite provar se ele é legítimo ou malicioso; o cenário pressupõe que os emissores legítimos já estejam estabelecidos antes do ataque.

A métrica bytes/s continua sendo monitorada por par e exibida como sinal auxiliar, mas a decisão de bloqueio desta versão é baseada na anomalia de PPS agregado por destino.

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

## 6. Configuração

Os parâmetros são lidos de variáveis de ambiente com prefixo `SDN_DDOS_`. Os que não forem definidos usam o padrão.

| Variável | Padrão | Descrição |
| --- | ---: | --- |
| `SDN_DDOS_MONITOR_INTERVAL` | `5` | Segundos entre coletas de estatísticas |
| `SDN_DDOS_BASELINE_SAMPLES` | `5` | Amostras por destino para formar a linha de base estatística (mín. 2) |
| `SDN_DDOS_HISTORY_SIZE` | `20` | Janela deslizante de amostras normais do histórico estatístico |
| `SDN_DDOS_THRESHOLD_FACTOR` | `3` | Limite estatístico: média + fator × desvio padrão |
| `SDN_DDOS_MIN_RATE_FACTOR` | `1.5` | Taxa também deve superar média × fator |
| `SDN_DDOS_MINIMUM_PPS` | `10.0` | Piso absoluto do limite para evitar alertas quando a média é próxima de zero |
| `SDN_DDOS_REQUIRED_ANOMALIES` | `2` | Janelas anômalas consecutivas antes de bloquear |
| `SDN_DDOS_BLOCK_TIME` | `30` | Duração do bloqueio em segundos |
| `SDN_DDOS_SUMMARY_EVERY_CYCLES` | `6` | Imprime resumo a cada N ciclos (0 desativa) |
| `SDN_DDOS_LOG_LEVEL` | `INFO` | Nível de log |

Os testes devem ser realizados somente no ambiente controlado do Mininet.
