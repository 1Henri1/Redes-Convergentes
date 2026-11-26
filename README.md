# SDN DDoS Controller

Controlador SDN desenvolvido em Python com **OS-Ken, Open vSwitch e Mininet**. O projeto monitora o tráfego da rede, identifica comportamentos anômalos e aplica regras temporárias de bloqueio no switch usando OpenFlow 1.3.

A detecção utiliza duas abordagens complementares:

- **DoS:** análise de taxas de pacotes por segundo (PPS) e bytes por segundo (bytes/s), com comparação em relação à baseline de tráfego e confirmação por anomalias consecutivas.
- **DDoS:** análise da distribuição das origens por meio da entropia, buscando identificar tráfego concentrado ou distribuído de forma anormal.

## 1. Requisitos

Ambiente Debian/Ubuntu com Python 3, Mininet e Open vSwitch.

Instale os pacotes do sistema:

```bash
sudo apt update
sudo apt install python3 python3-venv mininet openvswitch-switch
```

Crie o ambiente virtual e instale as dependências do projeto:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

O controlador utiliza a biblioteca OS-Ken, declarada em `requirements.txt`.

## 2. Executar o experimento automático

O modo automático é a forma recomendada de executar o experimento. Ele cria a topologia Mininet e inicia uma sequência de tráfego normal, DoS e DDoS, sem exigir que os pings sejam iniciados manualmente.

**Terminal 1: iniciar o controlador**

Na raiz do repositório:

```bash
source .venv/bin/activate
python run_controller.py
```

**Terminal 2: iniciar a rede e o cenário**

```bash
sudo python3 tools/run_mininet.py --auto-ping-test
```

Acompanhe as mensagens de monitoramento, detecção e bloqueio no Terminal 1. O prompt do Mininet permanece disponível enquanto o cenário é executado em segundo plano. Ao final, encerre a rede com:

```text
mininet> exit
```

O encerramento também interrompe processos de ping ainda ativos e finaliza a exportação dos resultados.

### 2.1. Topologia e geração de tráfego

A topologia padrão contém **25 hosts conectados a um switch Open vSwitch**, com o controlador remoto OS-Ken. O destino dos testes é o host `h25`, cujo IP é `10.0.0.25`.

A divisão dos endereços IP é fixa no script `tools/run_mininet.py`:

| Tipo de tráfego | Hosts | Endereços IP | Comportamento |
|---|---|---|---|
| Normal | h1 a h10 | 10.0.0.1 a 10.0.0.10 | Tráfego de menor frequência, com parâmetros variáveis |
| DoS | h11 e h12 | 10.0.0.11 e 10.0.0.12 | Maior frequência de envio concentrada em poucas origens |
| DDoS | h13 a h24 | 10.0.0.13 a 10.0.0.24 | Várias origens enviando tráfego simultaneamente |
| Destino | h25 | 10.0.0.25 | Recebe os pings dos demais hosts |

O AutoPing é implementado em `tools/ping_scenario.py`. Ele inicia automaticamente os comandos ping e executa uma sequência de etapas:

1. Duas etapas iniciais de tráfego normal, uma com hosts h1 a h5 e outra com h6 a h10.
2. Etapas adicionais sorteadas entre tráfego normal, DoS e DDoS.
3. Ao final, aguarda os comandos ping terminarem e exporta o CSV com a classificação das execuções.

Por padrão, são executadas **10 etapas no total**: duas etapas normais obrigatórias e oito etapas sorteadas. Em cada sorteio, as probabilidades são de 80% para normal, 10% para DoS e 10% para DDoS. Essas probabilidades definem o tipo de etapa, não garantem que todos os hosts daquele grupo iniciarão um ping: cada origem também possui uma probabilidade individual de 80% de ser ativada.

Os parâmetros de geração são aleatorizados dentro de faixas definidas no código:

| Tipo | Intervalo entre pacotes | Quantidade de pacotes | Tamanho do payload |
|---|---:|---:|---:|
| Normal | 0,05 a 0,12 s | 200 a 300 | 50 a 85 bytes |
| DoS | 0,01 a 0,04 s | 500 a 700 | 50 a 125 bytes |
| DDoS | 0,02 a 0,05 s | 200 a 300 | 50 a 85 bytes |

Os intervalos menores representam maior frequência de envio. No cenário DDoS, as origens são iniciadas com pequenas pausas entre si, permitindo que várias fontes gerem tráfego concorrente.

### 2.2. Personalização do AutoPing

Os parâmetros do cenário automático são alterados diretamente nos métodos da classe `PingScenario`, em `tools/ping_scenario.py`. Não há, atualmente, opções de linha de comando para esses ajustes.

**Número total de etapas:** no método `main()`, altere a condição:

```python
while cont < 10:
```

O valor `10` representa o total de etapas, incluindo as duas etapas normais iniciais. Por exemplo, `while cont < 14:` executa 14 etapas: duas normais obrigatórias e 12 sorteadas. O valor deve ser maior que 2 para manter etapas aleatórias após a inicialização.

**Probabilidades dos tipos de tráfego:** no mesmo método, altere os pesos:

```python
tipo = rd.choices(
    ["normal", "dos", "ddos"],
    weights=[80, 10, 10],
    k=1,
)[0]
```

A ordem dos pesos corresponde à lista de tipos. Por exemplo, `weights=[60, 20, 20]` define probabilidades de 60% para normal, 20% para DoS e 20% para DDoS. Os pesos são relativos; não precisam necessariamente somar 100, pois são normalizados pelo sorteio.

**Probabilidade de ativação de cada origem:** nos métodos `Normal()`, `AtaqDos()` e `AtaqDDos()`, altere a condição:

```python
if rd.random() < 0.8:
```

O valor `0.8` equivale a 80% de chance de cada host iniciar seu comando ping. Por exemplo, `0.5` representa 50%. Essa probabilidade é independente da probabilidade de escolha do tipo de etapa.

**Intensidade e duração dos pings:** os parâmetros são definidos em cada chamada de `start_pings()`:

- `interval=rd.uniform(min, max)`: sorteia o intervalo entre pacotes, em segundos. Diminuir os limites aumenta a frequência de envio.
- `count=rd.randint(min, max)`: sorteia a quantidade de pacotes enviados por origem.
- `packet_size=rd.randint(min, max)`: sorteia o tamanho do payload ICMP, em bytes.

Altere as faixas nos métodos `Normal()`, `AtaqDos()` e `AtaqDDos()` para modificar cada comportamento separadamente. Por exemplo, para aumentar a intensidade do DoS, pode-se reduzir a faixa de `interval` ou aumentar a faixa de `count`.

**Pausas entre as origens e etapas:** as chamadas a `self.wait(rd.uniform(min, max))` controlam as pausas em segundos. Nos métodos de geração, elas definem o intervalo entre o início dos hosts; em `main()`, a pausa ao final de cada etapa sorteada. Ajustá-las altera a sobreposição temporal dos tráfegos.

### 2.3. Resultado dos comandos ping

Ao terminar o cenário, é gerado o arquivo `resultado_comandos_ping.csv`, com uma linha por origem:

| Coluna | Significado |
|---|---|
| `Origem` | Nome do host de origem |
| `IP` | Endereço IP da origem |
| `Normais` | Comandos ping sem interseção com um bloqueio |
| `Bloqueadas` | Comandos ping cujo período coincidiu com um bloqueio da origem |
| `Total` | Total de comandos contabilizados |

A classificação considera o intervalo real de execução de cada comando. Assim, uma execução é contabilizada como bloqueada quando o período entre seu início e término intersecta algum evento de bloqueio registrado para o IP de origem. O CSV contabiliza **execuções de comandos ping**, e não pacotes ICMP individuais.

O caminho do arquivo CSV pode ser alterado pela variável de ambiente `SDN_DDOS_PING_RESULTS_PATH`. O arquivo de eventos de bloqueio pode ser configurado por `SDN_DDOS_BLOCK_EVENTS_PATH`; controlador e gerador devem utilizar o mesmo caminho.

## 3. Configuração do detector

Os parâmetros ficam em `sdn_ddos/config.py`. Também podem ser sobrescritos por variáveis de ambiente com o prefixo `SDN_DDOS_`. Por exemplo:

```bash
export SDN_DDOS_REQUIRED_ANOMALIES=3
python run_controller.py
```

Principais parâmetros:

| Parâmetro | Padrão | Função |
|---|---:|---|
| `monitor_interval` | 2 s | Intervalo entre ciclos de monitoramento |
| `report_interval` | 4 s | Intervalo entre relatórios |
| `baseline_samples` | 5 | Quantidade de amostras para formar a baseline |
| `history_size` | 20 | Tamanho do histórico utilizado pelo detector |
| `threshold_factor` | 3.0 | Fator aplicado ao desvio padrão para limites de taxa |
| `minimum_pps` | 5.0 | Taxa mínima considerada pelo detector |
| `required_anomalies` | 2 | Anomalias consecutivas necessárias para confirmação |
| `block_time` | 30 s | Duração do bloqueio temporário |
| `entropy_threshold_factor` | 3.0 | Fator do limite estatístico de entropia |
| `minimum_entropy_factor` | 1.2 | Fator mínimo utilizado na análise de entropia |
| `minimum_distributed_sources` | 2 | Número mínimo de origens para análise distribuída |

O indicador `ANOMALIA x/y` mostra a sequência observada e o número de confirmações exigido. Para alterar o valor efetivo, edite `required_anomalies` ou defina `SDN_DDOS_REQUIRED_ANOMALIES`. Variáveis de ambiente têm prioridade sobre os valores padrão do arquivo.

## 4. Parâmetros da rede Mininet

O script `tools/run_mininet.py` permite ajustar as características dos enlaces:

| Opção | Padrão | Descrição |
|---|---:|---|
| `--bw` | 10 Mbps | Largura de banda por enlace |
| `--delay` | 100us | Atraso configurado por enlace |
| `--jitter` | 0 | Variação de atraso |
| `--queue` | 100 | Tamanho máximo da fila em pacotes |
| `--loss` | 0% | Perda artificial de pacotes |
| `--auto-ping-test` | desativado | Inicia o cenário automático |

Exemplo de execução com parâmetros personalizados:

```bash
sudo python3 tools/run_mininet.py --auto-ping-test --bw 10 --delay 100us --queue 100 --loss 0
```

## 5. Testes e limpeza

Para executar os testes automatizados do projeto:

```bash
source .venv/bin/activate
pip install pytest
pytest -q tests
```

Para limpar configurações e processos residuais do Mininet:

```bash
sudo mn -c
```

> Execute os experimentos somente em uma rede Mininet controlada. Os bloqueios são aplicados pelo controlador ao tráfego da topologia de teste.
