# Modelo de concorrência e regiões críticas — Fase 2

Documento da **entrega 3** da Fase 2. Descreve como o `proxy_mitm.py` atende
múltiplas sessões simultâneas e quais são as regiões críticas (estado
compartilhado entre threads) e como são protegidas.

## 1. Modelo de concorrência

O proxy usa **threads da biblioteca padrão** (`threading`), coerente com o
servidor da Fase 1 (uma thread por cliente). Há três papéis:

```
                       ┌──────────────────────────────┐
  thread principal ───►│ accept() em laço              │  (aceita conexões)
                       └──────────────┬───────────────┘
                                      │ por cliente: abrir_sessao()
                        ┌─────────────┴──────────────┐
                        │ conecta ao servidor real   │
                        │ e sobe DUAS threads:        │
                        │   • relay C->S              │  (cliente  → servidor)
                        │   • relay S->C              │  (servidor → cliente)
                        └────────────────────────────┘
```

- A **thread principal** só faz `accept()` e, para cada cliente, dispara uma
  thread `abrir_sessao` (daemon). Assim, aceitar um novo cliente nunca espera o
  anterior terminar.
- Cada **sessão** abre a conexão ao servidor e sobe **duas threads de relay**,
  uma por sentido (`repassar(sessao, "C->S")` e `repassar(sessao, "S->C")`).
  Cada thread bloqueia em `recv()` de um lado e escreve com `sendall()` no outro.
- Para **N** sessões simultâneas há, portanto, **2N + 1** threads.

**Por que threads (e não um laço `select`/async):** o trabalho de um relay é
**I/O-bound** — fica a maior parte do tempo bloqueado em `recv()` esperando a
rede. Nesse cenário o GIL do CPython não é gargalo (ele é liberado durante a
chamada de socket bloqueante), e o código fica direto de ler. Uma thread
dedicada por sentido evita a complexidade de multiplexar leitura/escrita e deixa
claras as regiões críticas (abaixo).

## 2. Isolamento entre sessões

Sessões **não compartilham** estado de protocolo entre si: cada `Sessao` tem seus
próprios sockets e seu próprio buffer de linha. Logo, **a maior parte do código
não precisa de trava** — duas sessões diferentes nunca tocam no mesmo dado.

Isso também sustenta a **robustez** (requisito 4): toda a sessão roda dentro de
um `try/except` em `repassar`; uma desconexão abrupta (`ConnectionResetError`,
`BrokenPipeError`, `OSError`) ou uma linha inesperada é capturada e encerra
**apenas aquela** sessão. Ao sair, o bloco `finally` faz `shutdown()` dos dois
sockets para **destravar a thread irmã** (a do outro sentido), que está bloqueada
em `recv()`; as demais sessões seguem intactas.

## 3. Regiões críticas (estado compartilhado) e proteção

Há exatamente **três** pontos de estado compartilhado:

| # | Recurso compartilhado | Quem acessa | Proteção |
|---|-----------------------|-------------|----------|
| 1 | **Saída padrão (`stdout`)** — o log do proxy | todas as threads de todas as sessões | `_lock_log` (um `threading.Lock` global): a função `log()` imprime cada linha dentro do lock |
| 2 | **Contador de IDs de sessão** (`_seq_sessao`) | a thread principal, a cada `accept()` | `itertools.count`, cujo `next()` é atômico sob o GIL; o número ainda é impresso via `log()` (sob o lock #1) |
| 3 | **Campo `_usuario` de uma `Sessao`** | a thread **C->S** escreve (ao ver o `LOGIN`); a thread **S->C** lê (ao forjar a resposta) | `Sessao._lk` (um `threading.Lock` por sessão), via `set_usuario()` / `get_usuario()` |

### 3.1. Região #1 — o log (`_lock_log`)
Sem serializar a escrita, as linhas de várias sessões se **intercalariam no meio
de uma mesma linha**, tornando a evidência ilegível. O lock garante que cada
registro saia inteiro. É a única região crítica **global** acessada com
frequência; como o trecho protegido é só o `print`, a contenção é desprezível.

### 3.2. Região #2 — o ID de sessão (`_seq_sessao`)
Serve só para numerar as sessões na saída (`sessão 1`, `sessão 2`, ...).
`itertools.count().__next__` é atômico no CPython, então não há corrida ao obter
o número; ele é exibido através do `log()`, já coberto pelo lock #1.

### 3.3. Região #3 — o usuário visto na sessão (`Sessao._lk`)
É a **única** região crítica *entre as duas threads de uma mesma sessão*. A
thread C->S registra o usuário do `LOGIN`; a thread S->C lê esse valor ao
transformar um `401` em `200 OK bem-vindo <usuario>` (flag `--forjar-ok`). O lock
por sessão evita ler o campo pela metade enquanto a outra thread o escreve. É um
lock **por sessão** (não global): sessões diferentes não disputam entre si.

## 4. Resumo

- **Paralelismo:** `accept` desacoplado + 2 threads por sessão ⇒ várias sessões
  ativas ao mesmo tempo (ver `relatorio/results/fase2/D_concorrencia_proxy.txt`,
  em que as sessões 1 e 2 permanecem abertas enquanto 3–6 entram e saem).
- **Travas mínimas e justificadas:** uma global para o log, uma atômica para o
  contador e uma por sessão para o campo compartilhado entre os dois sentidos.
- **Sem estado de protocolo compartilhado entre sessões** ⇒ falha ou desconexão
  de uma sessão não afeta as outras.
