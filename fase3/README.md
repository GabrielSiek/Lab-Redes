# Fase 3 — Defesa e detecção (TLS + autenticação por certificado + senhas com hash)

**Disciplina:** Laboratório de Redes de Computadores — Escola Politécnica / PUCRS
**Trabalho:** Interceptação e Defesa de um Protocolo de Aplicação
**Fase 3 — Defesa e detecção** (neutraliza os ataques das Fases 1 e 2)

> ⚠️ **Escopo e ética.** Todo o código é uma prova de conceito para uso
> **exclusivo** em laboratório isolado. A Fase 3 corrige, de propósito, as
> fragilidades que as Fases 1 e 2 exploraram no mesmo serviço-alvo.

---

## 1. Visão geral

A Fase 3 protege **o mesmo serviço de login** das fases anteriores, aplicando as
três defesas que fecham os buracos demonstrados:

| Defesa | Fecha o ataque de | Como |
|--------|-------------------|------|
| **TLS** (confidencialidade + integridade) | sniffer passivo (Fase 1) | o canal TCP é envolvido em `ssl`; o conteúdo trafega cifrado |
| **Certificado do servidor** (autenticação) | proxy MITM (Fase 2) | o cliente valida o certificado contra a CA; um MITM com outro certificado é recusado |
| **Senhas com hash** (PBKDF2 + salt) | leitura de credenciais no servidor | `usuarios.txt` em texto claro é substituído por `usuarios_hash.txt` |

O **protocolo de aplicação é idêntico** ao da Fase 1 (`LOGIN`, `200/401`,
`QUIT`, `221`). Só o **transporte** mudou (TCP → TLS) e o **armazenamento** de
senha (texto claro → hash). Assim o relatório mostra a mesma aplicação antes
(insegura) e depois (protegida).

| Arquivo | Papel |
|---------|-------|
| `servidor_tls.py` | serviço-alvo protegido (TLS + verificação de senha por hash) |
| `cliente_tls.py` | cliente que **valida** o certificado do servidor antes de enviar a senha |
| `mitm_tls_intercept.py` | atacante que tenta se passar pelo servidor (para a demo de **detecção**) |
| `gerar_certificados.sh` | gera CA, certificado do servidor e certificado de atacante |
| `gerar_hashes.py` | converte `usuarios.txt` em `usuarios_hash.txt` (PBKDF2+salt) |
| `demo_defesa.sh` | monta a topologia e executa toda a bateria de evidências |

Os arquivos da Fase 1 (`servidor.py`, `cliente.py`, `sniffer.py`,
`usuarios.txt`) e da Fase 2 (`fase2/proxy_mitm.py`) **não são alterados** — são
usados como os "atacantes" que agora falham contra a versão protegida.

## 2. Pré-requisitos

- **Python 3.8+** (usa apenas a biblioteca padrão: `ssl`, `socket`, `hashlib`,
  `hmac`, `threading`).
- **OpenSSL** (apenas para gerar os certificados, uma vez).
- Para a captura automatizada: **Linux + root** (o `demo_defesa.sh` usa
  *network namespaces* e `tcpdump`); o `sniffer.py` da Fase 1 também exige Linux.

## 3. Geração de certificados e hashes (uma vez)

```sh
cd fase3
./gerar_certificados.sh     # cria certs/ca.crt, certs/servidor.crt/.key, certs/atacante.crt/.key
python3 gerar_hashes.py     # cria usuarios_hash.txt a partir de ../usuarios.txt
```

O cliente confia apenas em `certs/ca.crt`. O certificado do servidor
(`servidor.crt`) é assinado por essa CA e tem o nome lógico `servidor-auth` no
campo SAN (verificado pelo cliente, independente do IP). O `atacante.crt` é
**auto-assinado** — a CA não o reconhece — e serve só para a demonstração de
detecção.

## 4. Execução manual (3 hosts)

### 4.1. Servidor protegido
```sh
python3 servidor_tls.py --host 0.0.0.0 --porta 5050 \
    --cert certs/servidor.crt --chave certs/servidor.key \
    --usuarios usuarios_hash.txt
```

### 4.2. Cliente (valida o certificado do servidor)
```sh
python3 cliente_tls.py --host 10.0.0.20 --porta 5050 \
    --cafile certs/ca.crt --usuario alice --senha S3nh4Secreta
# -> [TLS OK] servidor autenticado; 200 OK bem-vindo alice
```

> **Teste local (loopback).** Funciona em uma só máquina: use `--host 127.0.0.1`
> no cliente e `--host 127.0.0.1` no servidor (o SAN do certificado inclui
> `127.0.0.1` e `servidor-auth`).

### 4.3. Verificando que os ataques falham

**Sniffer da Fase 1 contra o TLS** (Linux, root): o sniffer captura os pacotes,
mas o payload é TLS cifrado — nenhuma linha `LOGIN ...` aparece, logo nenhuma
credencial é extraída.

**MITM tentando se passar pelo servidor** — aponte o cliente ao atacante:
```sh
# atacante (apresenta o certificado auto-assinado):
python3 mitm_tls_intercept.py --escuta 0.0.0.0:5050 --servidor 10.0.0.20:5050 \
    --cert certs/atacante.crt --chave certs/atacante.key
# cliente apontado ao atacante (10.0.0.30):
python3 cliente_tls.py --host 10.0.0.30 --porta 5050 --cafile certs/ca.crt \
    --usuario alice --senha S3nh4Secreta
# -> ATAQUE DETECTADO: CERTIFICATE_VERIFY_FAILED; a senha NAO e enviada (exit 3)
```

## 5. Reprodução automática + capturas (Linux, root)

O [`demo_defesa.sh`](demo_defesa.sh) monta a topologia com *network namespaces*
(cliente `10.0.0.10`, atacante `10.0.0.30`, servidor `10.0.0.20`, numa bridge) e
executa, capturando o tráfego com `tcpdump`, os quatro experimentos:

```sh
sudo ./demo_defesa.sh            # saída em ./saida_demo/
```

| Saída | Mostra |
|-------|--------|
| `antes.pcap` | login em texto claro (Fase 1): a senha é legível na rede |
| `depois.pcap` | login com TLS (Fase 3): só `Application Data` cifrada |
| `sniffer_tls.txt` | o sniffer da Fase 1 não extrai nenhuma credencial do TLS |
| `mitm.pcap` + `mitm_cliente.txt` | o cliente detecta o MITM (`Alert: Unknown CA`) e aborta |

## 6. Ambiente de teste (transparência)

Os três hosts foram isolados com **network namespaces do Linux** ligados por uma
bridge — **o mesmo ambiente das Fases 1 e 2**, equivalente a três VMs em uma
rede isolada para efeito de captura (cada host tem IP próprio e o tráfego
atravessa a bridge, não a interface de loopback). Os IPs e nomes de host que
aparecem nos logs e capturas (`10.0.0.10/20/30`) correspondem exatamente a essa
topologia.

## 7. O que a defesa cobre e o que não cobre

- **Cobre:** leitura de conteúdo (sniffing), adulteração de mensagens e
  personificação do servidor (MITM), e leitura de senhas no servidor.
- **Não cobre:** metadados ainda visíveis (IPs, portas, tamanho e tempo dos
  pacotes); comprometimento de um endpoint; e, como só o servidor é autenticado
  por certificado, o servidor confia no cliente apenas pela senha (mTLS seria uma
  extensão). A análise completa está no relatório final consolidado.
