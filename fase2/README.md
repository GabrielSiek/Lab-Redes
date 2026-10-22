# Fase 2 — Interceptação ativa (MITM concorrente)

**Disciplina:** Laboratório de Redes de Computadores — Escola Politécnica / PUCRS
**Trabalho:** Interceptação e Defesa de um Protocolo de Aplicação
**Fase 2 — Interceptação ativa (Man-in-the-Middle)** (demonstra a quebra de integridade e de autenticação)

> ⚠️ **Escopo e ética.** Este proxy é uma **prova de conceito** para uso
> **exclusivo** em um laboratório **isolado** (VMs do próprio grupo). Ele explora
> o fato de o protocolo da Fase 1 trafegar em texto claro **sem integridade nem
> autenticação**; a correção é a Fase 3. Não utilize fora do laboratório fechado.

---

## 1. Visão geral

A Fase 2 acrescenta **um único componente novo** ao alvo da Fase 1: um **proxy
man-in-the-middle** que se posiciona entre o cliente e o servidor. O cliente e o
servidor da Fase 1 **não são alterados** — o desvio do tráfego é feito **por
configuração**, apontando o cliente para o proxy (`cliente.py --host <proxy>`).

| Arquivo          | Papel                                                        | Onde roda        |
|------------------|--------------------------------------------------------------|------------------|
| `proxy_mitm.py`  | Proxy MITM concorrente: faz o *relay* e pode ler/alterar as mensagens | VM-atacante |
| `demo_mitm.sh`   | (apoio) monta 3 *namespaces* e roda a demonstração automaticamente | Linux (root) |
| `concorrencia.md`| Documento do modelo de concorrência e das regiões críticas   | —                |
| `servidor.py` / `cliente.py` / `usuarios.txt` | Reutilizados **sem alteração** da Fase 1 | VM-servidor / VM-cliente |

Para cada cliente, o proxy: **(1)** aceita a conexão do cliente; **(2)** abre a
conexão ao servidor real; **(3)** repassa as mensagens nos dois sentidos,
podendo **inspecionar e adulterar** cada linha. Usa **somente sockets** da
biblioteca padrão (sem frameworks).

## 2. Topologia de redirecionamento (laboratório isolado)

A antiga **VM-observador** da Fase 1 passa a ser a **VM-atacante**, rodando o
proxy. O cliente é **reconfigurado** para conectar no proxy, e o proxy encaminha
para o servidor real.

```
             Rede interna isolada (ex.: 10.0.0.0/24) — sem Internet
 ┌──────────────────────────────────────────────────────────────────────────┐
 │                                                                            │
 │  ┌───────────────┐        ┌────────────────┐        ┌──────────────────┐  │
 │  │  VM-cliente   │        │  VM-atacante   │        │   VM-servidor    │  │
 │  │  cliente.py   │        │  proxy_mitm.py │        │   servidor.py    │  │
 │  │  10.0.0.10    │        │   10.0.0.30    │        │    10.0.0.20     │  │
 │  └───────┬───────┘        └───┬────────┬───┘        └────────┬─────────┘  │
 │          │  TCP 5050          │        │   TCP 5050          │            │
 │          └──────────►─────────┘        └─────────►───────────┘            │
 │        (cliente --host 10.0.0.30)        (proxy --servidor 10.0.0.20:5050) │
 │                                                                            │
 └──────────────────────────────────────────────────────────────────────────┘
```

O desvio **não** usa ARP spoofing nem proxy transparente: é o próprio cliente
que é apontado ao proxy, como pede o enunciado ("redirecionamento por
configuração do próprio serviço").

## 3. Pré-requisitos

- **Python 3.8+** nas VMs (`python3 --version`).
- Nenhuma biblioteca externa — apenas a biblioteca padrão.
- O proxy é **multiplataforma** (TCP puro; não usa socket raw), então roda em
  Windows/Linux/macOS. O script de apoio `demo_mitm.sh` exige **Linux + root**
  (usa *network namespaces*).

## 4. Como executar (3 VMs)

### 4.1. VM-servidor (inalterada — Fase 1)
```bash
python3 servidor.py --host 0.0.0.0 --porta 5050
```

### 4.2. VM-atacante (proxy) — inicie ANTES do cliente
```bash
# relay transparente (só lê e registra o tráfego)
python3 proxy_mitm.py --escuta 0.0.0.0:5050 --servidor 10.0.0.20:5050

# com adulteração (ver seção 5)
python3 proxy_mitm.py --escuta 0.0.0.0:5050 --servidor 10.0.0.20:5050 --forjar-ok
```

### 4.3. VM-cliente (apontada ao proxy, não ao servidor)
```bash
python3 cliente.py --host 10.0.0.30 --porta 5050 --usuario bob --senha senhaERRADA
```

> **Teste em uma só máquina (loopback).** Como o proxy é TCP puro, dá para
> validar tudo localmente sem VMs, usando portas distintas: servidor em `:5050`,
> proxy escutando em `:5151` e encaminhando para `127.0.0.1:5050`, e o cliente
> em `:5151`:
> ```bash
> python3 servidor.py --host 127.0.0.1 --porta 5050
> python3 proxy_mitm.py --escuta 127.0.0.1:5151 --servidor 127.0.0.1:5050 --forjar-ok
> python3 cliente.py --host 127.0.0.1 --porta 5151 --usuario bob --senha senhaERRADA
> ```

## 5. Adulteração de mensagens (requisito 2 e 5)

O proxy inspeciona cada linha do protocolo e aplica regras selecionáveis por
*flag*. Linhas fora do padrão esperado passam **inalteradas**.

| Flag                     | Sentido | Efeito | O que demonstra |
|--------------------------|---------|--------|-----------------|
| `--forjar-ok`            | S → C   | reescreve `401 ERRO ...` como `200 OK bem-vindo <usuario>` | o cliente **aceita como legítima** uma resposta que o servidor **não** enviou (quebra de autenticação/integridade) |
| `--trocar-senha <valor>` | C → S   | substitui a senha na linha `LOGIN` | um **valor** em trânsito é adulterado e o servidor o aceita como legítimo |
| `--trocar-usuario <nome>`| C → S   | substitui o usuário na linha `LOGIN` | um **comando** é adulterado e o servidor age sobre ele sem detectar |

Nenhuma das flags é obrigatória: sem flags, o proxy é um *relay* transparente
que apenas **lê** (registra) todo o tráfego — já evidenciando o posicionamento
no meio da conexão.

### Demonstração-chave (resposta forjada)
```
cliente:  >> LOGIN bob senhaERRADA
          << 200 OK bem-vindo bob          (cliente acredita ter autenticado)
proxy:    S->C ADULTERADA: '401 ERRO credenciais invalidas' -> '200 OK bem-vindo bob'
servidor:   127.0.0.1:... LOGIN FALHOU usuario='bob'   (o servidor REJEITOU)
```
A divergência entre o que o servidor registrou (`FALHOU`) e o que o cliente
recebeu (`200 OK`) é a prova da adulteração sem detecção.

## 6. Concorrência e robustez

- **Concorrência:** o proxy atende **múltiplas sessões simultâneas** — uma thread
  por sentido de cada sessão. O modelo e as **regiões críticas** estão descritos
  em [`concorrencia.md`](concorrencia.md).
- **Robustez:** cada sessão é isolada; uma **desconexão abrupta** ou uma
  **mensagem malformada** encerra/afeta **apenas aquela** sessão, sem derrubar as
  demais.

## 7. Reprodução automática (opcional, Linux)

O script [`demo_mitm.sh`](demo_mitm.sh) monta — com *network namespaces* — a
topologia das três VMs (cliente `10.0.0.10`, atacante `10.0.0.30`, servidor
`10.0.0.20`), aponta o cliente ao proxy e executa automaticamente os cenários de
adulteração e de concorrência, gerando as saídas em `./saida_demo/`:

```bash
sudo ./demo_mitm.sh
# gera: saida_demo/proxy_*.txt, servidor_*.txt, cliente_*.txt
```

## 8. Arquivos entregues nesta fase

```
fase2/
├─ proxy_mitm.py     # proxy MITM concorrente (entrega 1)
├─ README.md         # este arquivo: topologia de redirecionamento (entrega 2)
├─ concorrencia.md   # modelo de concorrência e regiões críticas (entrega 3)
└─ demo_mitm.sh      # (apoio) monta 3 namespaces e roda a demonstração
relatorio/
├─ relatorio_fase2.pdf   # demonstração de leitura e modificação, com evidência (entrega 4)
└─ results/fase2/        # saídas do proxy/servidor/cliente usadas no relatório
```
