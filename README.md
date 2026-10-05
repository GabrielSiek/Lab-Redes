# Fase 1 — Aplicação-alvo em texto claro + Interceptador passivo

**Disciplina:** Laboratório de Redes de Computadores — Escola Politécnica / PUCRS
**Trabalho:** Interceptação e Defesa de um Protocolo de Aplicação
**Fase 1 — Reconhecimento e escuta passiva** (demonstra a quebra de confidencialidade)

> ⚠️ **Escopo e ética.** Todo o código aqui é uma **prova de conceito** para uso
> **exclusivo** em um laboratório **isolado** (VMs do próprio grupo). O protocolo
> é inseguro **de propósito** — credenciais em texto claro — para que a Fase 1
> tenha o que demonstrar e a Fase 3 o que proteger. Não utilize fora do
> laboratório fechado.

---

## 1. Visão geral

Três componentes, todos em Python 3 e usando **sockets diretamente** (sem
frameworks que escondam o socket):

| Arquivo         | Papel                                | Onde roda              |
|-----------------|--------------------------------------|------------------------|
| `servidor.py`   | Serviço-alvo: autenticação em texto claro (TCP) | VM-servidor |
| `cliente.py`    | Cliente que envia usuário/senha      | VM-cliente             |
| `sniffer.py`    | Interceptador passivo com **socket raw** (`AF_PACKET`) | VM-observador (Linux, root) |
| `usuarios.txt`  | Base de credenciais (texto claro)    | VM-servidor         |

O serviço-alvo é **multiplataforma** (Windows/Linux/macOS). O **sniffer exige
Linux** com privilégio de root, pois usa o socket raw `AF_PACKET`/`ETH_P_ALL`
(padrão da camada de enlace no Linux).

## 2. Topologia da rede (laboratório isolado)

Monte uma **rede interna/host-only** (sem saída para a Internet), com pelo menos
três VMs no mesmo domínio de enlace (mesmo switch virtual). A VM-observador deve
estar em **modo promíscuo** e, em switches virtuais, ver o tráfego do segmento
(use *hub mode* / *Allow Promiscuous* / espelhamento de porta).

```
                 Rede interna isolada (ex.: 10.0.0.0/24) — sem Internet
   ┌────────────────────────────────────────────────────────────────────────┐
   │                                                                        │
   │   ┌───────────────┐          ┌───────────────┐        ┌──────────────┐ │
   │   │  VM-cliente   │          │  VM-servidor  │        │ VM-observador│ │
   │   │  cliente.py   │          │  servidor.py  │        │  sniffer.py  │ │
   │   │  10.0.0.10    │          │  10.0.0.20    │        │  10.0.0.30   │ │
   │   └───────┬───────┘          └───────┬───────┘        └──────┬───────┘ │
   │           │        TCP 5050          │                       │         │
   │           │   (LOGIN usuario senha)  │     escuta passiva    │         │
   │           └───────────►──────────────┘◄╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘         │
   │                   (texto claro)            (modo promíscuo)            │
   │                                                                        │
   └────────────────────────────────────────────────────────────────────────┘
```

O cliente conecta-se ao servidor na porta **TCP 5050**. O observador não
participa da conexão: apenas lê os quadros que passam pelo segmento e reconstrói
o conteúdo da aplicação.

## 3. Pré-requisitos

- **Python 3.8+** nas três VMs (`python3 --version`).
- **VM-observador:** Linux com acesso **root** (o socket raw exige `CAP_NET_RAW`).
- (Opcional) **Wireshark/tshark** para a evidência pacote-a-pacote.
- Nenhuma biblioteca externa é necessária — apenas a biblioteca padrão.

## 4. Como executar

### 4.0. Reprodução automática (um comando, sem montar VMs)

Para quem quer demonstrar tudo rapidamente **sem criar três VMs**, o script
[`demo_topologia.sh`](demo_topologia.sh) monta — com *network namespaces* do
Linux — três "hosts" isolados (cliente `10.0.0.10`, servidor `10.0.0.20` e
observador `10.0.0.30`) ligados por um switch virtual em **modo hub**, e executa
sozinho o servidor, o sniffer e várias sessões de cliente, gerando a captura:

```bash
sudo ./demo_topologia.sh            # saída em ./saida_demo/
# gera: saida_demo/captura.pcap, sniffer_out.txt, servidor_out.txt
```

Como são hosts separados numa rede real (e não `lo`), a captura sai **sem a
duplicação de pacotes do loopback**. É o mesmo cenário das três VMs do enunciado,
apenas mais leve e automatizado — útil para desenvolvimento e para gerar a
evidência do relatório. A entrega "oficial" pode ser refeita nas VMs seguindo os
passos manuais abaixo (basta trocar o `.pcap`/prints pelos do seu ambiente).

### 4.1. VM-servidor
```bash
python3 servidor.py --host 0.0.0.0 --porta 5050
# usa fase1/usuarios.txt por padrão (--usuarios para outro arquivo)
```

### 4.2. VM-observador (Linux, como root) — inicie ANTES do cliente
```bash
# Descubra a interface do segmento isolado (ex.: eth0) com: ip -o link show
sudo python3 sniffer.py --interface eth0 --porta 5050 --pcap captura.pcap
```
O sniffer imprime cada segmento com payload, numerado, e **destaca as
credenciais** capturadas. O arquivo `captura.pcap` pode ser aberto no Wireshark.

### 4.3. VM-cliente
```bash
# modo não interativo (bom para demonstração)
python3 cliente.py --host 10.0.0.20 --porta 5050 --usuario alice --senha S3nh4Secreta

# modo interativo (pede usuário e senha no terminal)
python3 cliente.py --host 10.0.0.20 --porta 5050
```

### 4.4. Credenciais de teste (`usuarios.txt`)
`alice:S3nh4Secreta`, `bob:123456`, `carol:qwerty2026`, `admin:admin`.

## 5. Protocolo da aplicação (texto, uma linha por mensagem, `\n`)

| Sentido | Mensagem                              | Significado                 |
|---------|---------------------------------------|-----------------------------|
| S → C   | `200 AUTH-SERVICE v1 pronto`          | banner, ao conectar         |
| C → S   | `LOGIN <usuario> <senha>`             | tentativa de autenticação   |
| S → C   | `200 OK bem-vindo <usuario>`          | credenciais válidas         |
| S → C   | `401 ERRO credenciais invalidas`      | credenciais inválidas       |
| S → C   | `400 ERRO comando malformado`         | sintaxe inválida            |
| C → S   | `QUIT`                                | encerra a sessão            |
| S → C   | `221 tchau`                           | confirmação de encerramento |

## 6. Evidência da captura (Wireshark)

Abra `captura.pcap` no Wireshark (ou use `tshark -r captura.pcap`). Para ver o
conteúdo legível de uma sessão: clique com o botão direito em um pacote TCP →
**Follow → TCP Stream**. A credencial `LOGIN alice S3nh4Secreta` aparece **em
texto claro**, provando a quebra de confidencialidade. Os números de pacote
(frames) são listados no relatório.

## 7. Observações técnicas

- **Concorrência:** o servidor trata cada cliente em uma *thread* dedicada, já
  preparando a base para a Fase 2 (múltiplas conexões simultâneas).
- **Captura em loopback:** se cliente, servidor e sniffer rodarem na **mesma**
  máquina (interface `lo`), cada segmento é entregue **duas vezes** pelo
  `AF_PACKET` (cópia de envio + recepção); o Wireshark marca as cópias como
  *TCP Retransmission*. No laboratório real (três VMs distintas) isso **não**
  ocorre. Para deduplicar uma captura de loopback: `editcap -d captura.pcap captura_limpa.pcap`.
- **Por que Linux no observador:** `AF_PACKET` é a API de captura de enlace do
  Linux. No Windows a captura raw tem limitações (não vê loopback, exige
  `SIO_RCVALL`), por isso o observador do laboratório é uma VM Linux.

## 8. Arquivos entregues nesta fase

```
fase1/
├─ servidor.py          # serviço-alvo (cliente/servidor do protocolo)
├─ cliente.py           # cliente do serviço-alvo
├─ sniffer.py           # interceptador passivo (socket raw)
├─ usuarios.txt         # base de credenciais (texto claro)
├─ demo_topologia.sh    # monta 3 hosts (namespaces) e roda tudo (opcional)
└─ README.md            # este arquivo (topologia + execução)
relatorio/
├─ relatorio_fase1.pdf   # relatório com a evidência de captura
└─ figuras/              # pcap e saídas usadas no relatório
```
