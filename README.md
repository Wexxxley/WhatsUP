# WhatsUp — Sistema de Mensageria Multi-Cliente (E2E)

## Visão geral

O WhatsUp é uma aplicação de mensageria com criptografia ponta a ponta (E2E).
Clientes trocam mensagens cifradas, enquanto o servidor atua como relay: ele gerencia conexões e encaminha frames, mas não
decifra o conteúdo das mensagens E2E.

Cada cliente cria um identificador UUID e um par de chaves assimétricas X25519 toda vez que o cliente é reiniciado. 
O cliente autentica o servidor durante o handshake, registra sua chave pública
e recebe os anúncios feito pelo servidor dos peers online.

### Garantias e mecanismos

1. **Confidencialidade:** AES-128-GCM cifra o conteúdo das mensagens.
2. **Integridade:** a tag de autenticação do AESGCM detecta adulterações;
3. **Validação do handshake:** o cliente compara o certificado recebido com
   `certs/server.crt` e verifica a assinatura RSA-PSS correspondente.
4. **Sigilo futuro:** pares efêmeros X25519 são usados para
   derivar chaves E2E por sessão.
5. **Proteção contra replay:** contadores de sequência por direção rejeitam
   mensagens repetidas ou fora de ordem.

## Navegação

- [Estrutura do projeto](#estrutura-do-projeto)
- [Pré-requisitos e execução](#pre-requisitos-e-execucao)
- [Conceitos usados no protocolo](#conceitos-usados-no-protocolo)
- [Fluxo do protocolo](#fluxo-do-protocolo)
- [Exemplo dos contadores por cliente](#exemplo-dos-contadores-por-cliente)
- [Assinatura digital não é criptografia](#assinatura-digital-nao-e-criptografia)
- [Dicionário de termos](#dicionario-de-termos-e-mapeamento-com-os-estudos)
- [Observações sobre X25519 e ECDH](#observacoes-sobre-x25519-e-ecdh)

---

## Execução


```bash
python3 -m pip install cryptography
```

Em um terminal, inicie o servidor:

```bash
python3 server.py
```

Em outro terminal, inicie cada cliente:

```bash
python3 client.py
```

Execute os testes unitários e de integração:

```bash
python3 -m unittest discover -s tests
```
---

## Diagrama de sequência


![Diagrama de sequência do protocolo WhatsUp](/public/DiagramaDeSequencia-WhatsUP.svg)

## FASE 0: Credenciais (Servidor)

O WhatsUp usa dois tipos de criptografia com finalidades diferentes:

- **Assimétrica:** usa um par de chaves pública e privada. Nesta fase, o
  servidor usa RSA para assinar o handshake. X25519 também usa chaves
  assimétricas, mas para os peers derivarem um segredo compartilhado na FASE 5.
- **Simétrica:** usa a mesma chave secreta para cifrar e decifrar. O WhatsUp usa
  AES-128-GCM para proteger as mensagens na FASE 6.

![](/public/Criptografias.png)

`server.crt` é um certificado X.509 autoassinado que contém a chave pública RSA
do servidor e a identidade `tp3-server`. É público e pode ser compartilhado.
A chave privada correspondente é usada para assinar o handshake e não deve ser
compartilhada.

Durante a inicialização, `server.py` chama
`load_or_generate_server_credentials()`. Na primeira execução, essa função gera
o par RSA e grava `certs/server.crt` e `certs/server.key`; depois, reutiliza os
dois arquivos. A chave privada permanece local, não é enviada pela rede nem
registrada nos logs, e `server.key` é ignorado pelo Git.

O cliente compara o certificado recebido no handshake com esse arquivo e usa a
chave pública nele contida para verificar a assinatura RSA-PSS. Como o certificado é persistente e não é regenerado a cada inicialização, essa
comparação funciona como pinning local do servidor.

## FASE 1: Registro (Cliente)

Quando um cliente é iniciado:

1. **Gera sua id:** um **UUID v4** de 16 bytes.
2. **Gera par de chaves X25519:** `sk_a` (privada) e `pk_a` (pública). São efêmeras: nascem e morrem com esta execução do cliente.
3. Conecta via ao servidor.
4. **Envia o frame de registro:** `Pre(4B) || id_a(16B) || pk_a(32B)`. 
- **Prefixo:** informa, em 4 bytes, o tamanho do payload que vem depois dele.

**FRAME**: O TCP é um **fluxo de bytes sem fronteiras de mensagem**. Por isso todo frame começa com `Pre`, um prefixo de **4 bytes big-endian** declarando o tamanho do payload. 


## FASE 2: Handshake (Servidor)

Assim que o registro chega, o servidor responde provando quem é:

1. Recebe `id_a` e `pk_a`.
2. **Gera um `salt` aleatório** para esta sessão.
4. **Monta o material do handshake:** `pk_S || pk_a || id_a || salt`.
5. **Calcula** `H = SHA256(material)` e assina `H` com **RSA-PSS + SHA-256**, usando sua chave privada.
6. **Responde ao cliente:** `(certificado, assinatura, salt)`.


### Conceito: assinatura digital

Com RSA-PSS, o servidor usa sua chave **privada** para gerar uma assinatura
associada ao material do handshake. O cliente usa a
chave **pública** correspondente para verificar se a assinatura confere com
esse material.


**Assinatura não é criptografia:** Quando o servidor calcula
`H = SHA256(pk_S || pk_C || client_id || salt_srv)` e assina esse com a
chave privada, ele não cifra os dados originais. A
assinatura permite verificar a integridade e a correspondência com a chave
pública do certificado; o material e o certificado trafegam em claro junto
dela.

A resposta do handshake contém:

```text
[tamanho do certificado] ||
[server.crt (contendo pk_S)] ||
[tamanho da assinatura] ||
[assinatura] ||
[salt_srv]
```

O cliente compara o certificado recebido com o arquivo local e verifica a
assinatura RSA-PSS com a chave pública do certificado. O mesmo certificado é usado para verificar 
os anúncios administrativos de peers.


### Conceito: salt

**Salt** é um valor aleatório usado como "tempero" de derivação, para que o mesmo material produza resultados diferentes em sessões diferentes. 

## FASE 3: Validação do handshake (Cliente)

1. **Compara o certificado:** compara o `cert` recebido com o `certs/server.crt` pinado localmente. Diferente → **conexão encerrada**.
2. **Extrai `pk_S`** do certificado.
3. **Remonta o material:** `pk_S || pk_a || id_a || salt` 
4. **Verifica a assinatura** RSA-PSS com `pk_S`. Inválida → **conexão encerrada**.

## FASE 4: Registro na sessão e anúncio dos peers (Servidor)

Com o handshake validado, o servidor integra o cliente à rede:

1. Sob a `sessions_lock` (`asyncio.Lock`) registra a sessão
2. Envia o número de peers online e os dados de cada um.
3. A partir daqui o Cliente A sabe quem está online e com quais chaves públicas.

Os anúncios de peers também são assinados pelo servidor e verificados com o
certificado pinado. Isso autentica a origem do anúncio contra atacantes de rede;
não protege contra um servidor comprometido, que possui a chave privada RSA.

## FASE 5: Derivação das chaves E2E

Cada cliente, ao conhecer um peer, executa independentemente, e chegando ao mesmo resultado:

1. **Calcula o segredo compartilhado:** `Z = sk.exchange(pk_do_peer)` com X25519. O Cliente A usa `sk_a` com `pk_b`; o Cliente B usa `sk_b` com `pk_a`. Ambos obtêm o mesmo segredo `Z`
2. **Deriva as duas chaves de direção com HKDF:**
   - `key_A2B = HKDF(salt=pair_salt, info=b"A2B", length=16)`
   - `key_B2A = HKDF(salt=pair_salt, info=b"B2A", length=16)`
3. **Define o papel pelo menor id:** se meu id < id do peer, sou o "A" deste par → `key_send = key_A2B` e `key_recv = key_B2A`; senão, o contrário. 
4. **Gera o `IV_base_send`:** 4 bytes aleatórios, a base dos nonces desta direção.

### Conceito: Diffie–Hellman

**Como duas partes que nunca se falaram criam um segredo comum, olhando apenas mensagens públicas?**

No X25519, todos os participantes usam a mesma curva e o mesmo gerador. 

```text
pk_A = sk_A · G
pk_B = sk_B · G
```
Para obter o segredo compartilhado, cada lado combina seu escalar privado com a chave pública recebida:

```text
Alice: Z_AB = sk_A · pk_B
Bob:   Z_AB = sk_B · pk_A
```

Ambos chegam ao mesmo ponto:

```text
sk_A · (sk_B · G) = sk_B · (sk_A · G)
```

A figura abaixo ilustra a mesma ideia com o DH clássico usando `mod p`. 
![](/public/dh.png)


HKDF transforma o segredo em material de chave apropriado, usando um salt e rótulos (`info`) para separar as chaves de cada direção. Ao contrário do Argon2, que é voltado
para derivação de chaves a partir de senhas e é deliberadamente custoso, HKDF é uma função rápida para derivar chaves de um segredo de entrada já forte.

Suponha:
- ID de Alice: `10`
- ID de Bob: `20`
- Ambos calculam o mesmo segredo ECDH: `Z`
- Ambos usam o mesmo `pair_salt`

A partir desses mesmos dados, os dois clientes derivam as mesmas duas chaves:

```text
key_A2B = 1111
key_B2A = 2222
```

Em `derive_e2e_keys`, o menor ID determina a direção. Alice tem o ID menor, então:

| Cliente | `key_send` | `key_recv` |
|---|---:|---:|
| Alice (ID `10`) | `1111` (`key_A2B`) | `2222` (`key_B2A`) |
| Bob (ID `20`) | `2222` (`key_B2A`) | `1111` (`key_A2B`) |

Assim:

- Quando Alice envia para Bob, cifra com `1111`; Bob recebe e decifra com `1111`.
- Quando Bob envia para Alice, cifra com `2222`; Alice recebe e decifra com `2222`.

## FASE 6: Cifragem E2E com AES-128-GCM (Cliente A)

Com chave em mãos, o cliente A escreve para B:

1. **Constrói o nonce (12 B):** `nonce = IV_base_send(4B) || seq_send(8B, big-endian)`. O contador embutido garante **nonce nunca repetido** enquanto a sessão viver — e repetir nonce sob GCM é o erro que destrói a chave.
2. **Constrói o AAD (40 B):** `sender_id(16B) || recipient_id(16B) || seq_no(8B)` — dados que serão autenticados, mas **não cifrados**.
3. **Cifra:** `AESGCM(key_send).encrypt(nonce, plaintext, aad)` → ciphertext com a **tag de 16 B** anexada.
4. **Envia o frame E2E** ao servidor, endereçado a `id_b`. O servidor **repassa intacto**: não pode ler (não tem a chave) nem adulterar (a tag pega na FASE 7).

### Conceito: criptografia simétrica

Na criptografia simétrica, **a mesma chave cifra e decifra** — é ordens de magnitude mais rápida que a assimétrica e por isso é a escolha natural para o conteúdo das mensagens. Seu desafio clássico é a **distribuição da chave**: como entregar a chave a B sem que ninguém a intercepte? O WhatsUp responde com a FASE 5 — a chave nunca é distribuída; ela é **derivada nos dois lados** a partir do segredo ECDH.

### Conceito: AES-GCM e AEAD

O **AES-128-GCM** é um modo **AEAD** (Authenticated Encryption with Associated Data): uma única operação entrega **confidencialidade + integridade + autenticidade**. A tag de 16 B é o "selo": decifrar com qualquer byte alterado — do ciphertext, do nonce ou do AAD — falha com `InvalidTag`. É por isso que um relay curioso pode adulterar quanto quiser: nada adulterado passa na FASE 7.

### Hash e AEAD

- **Hash:** função determinística e unidirecional que resume dados em um valor
  de tamanho fixo.
- AEAD (Criptografia autenticada com dados associados): é um padrão que os algoritmos de criptografia simétrica implementam (AES-GCM é um algoritmo AEAD) para garantir simultaneamente:
  - **Confidencialidade**: os dados são criptografados.
  - **Integridade**: qualquer modificação nos dados pode ser detectada por meio de uma falha na verificação da tag de autenticação durante a decifragem.
  - **Autenticidade**: garante que os dados vieram de uma fonte confiável.

  - **Dados associados (AAD)**: são informações que não são criptografadas, mas são incluídas no cálculo para gerar a tag de autenticação.
  - **Tag de autenticação**: é um código de verificação para garantir integridade.
  - **Nonce**: valor usado pelo AES-GCM em cada cifragem. Não é secreto e precisa ser único para cada mensagem cifrada com a mesma chave. Neste projeto, ele tem 12 bytes: 4 bytes de base aleatória seguidos por 8 bytes do número de sequência.


### Conceito: nonce e AAD — por que cada byte importa

- **Nonce (12 B):** precisa ser único por mensagem sob a mesma chave. Aqui ele é **deterministicamente único**: base aleatória de 4 B + contador de 8 B que cresce a cada envio. Com GCM, reutilizar o par (nonce, chave) é catastrófico — vaza a relação entre mensagens e permite falsificar tags. Este desenho elimina o risco por construção.
- **AAD (40 B):** metadados que **não são cifrados mas são autenticados**. O receptor reconstrói o AAD e o alimenta na decifragem; se alguém trocou `sender_id`, `recipient_id` ou `seq_no` no caminho, o AAD diverge → `InvalidTag`. Ou seja: o cabeçalho não é secreto, mas **é à prova de mentira**.

**Limites por frame** (`protocol/spec.py`):

| Campo | Valor |
|---|---|
| `Pre` (prefixo de tamanho) | 4 B, big-endian |
| Frame de transporte (máx.) | 4200 B |
| Payload E2E (máx.) | 4164 B = AAD (40 B) + nonce (12 B) + ciphertext+tag (≤ 4112 B) |
| Texto claro (máx.) | 4096 B (4096 + 16 de tag + 52 de cabeçalho E2E = 4164) |

## FASE 7: Recepção, anti-replay e decifragem (Cliente B)

O cliente B recebe um frame E2E e executa, nesta ordem:

1. **Validação anti-replay:** exige `seq_no == seq_recv + 1`, **exatamente**. Repetido, fora de ordem ou muito no futuro → **frame rejeitado** (descartado sem decifrar).
2. **Decifra:** `AESGCM(key_recv).decrypt(nonce, ciphertext+tag, aad)`.
3. **`InvalidTag` → falha imediata:** mensagem descartada; não há retentativa nem "aceitar mesmo assim".
4. **Atualiza o contador:** `seq_recv = seq_no`.
5. **Exibe o texto claro** no terminal.

A ordem importa: o anti-replay vem **antes** da decifragem, para que frames repetidos nem cheguem ao AES.

### Conceito: ataque de replay e os contadores por direção

**Replay** é o ataque em que o adversário **retransmite um frame legítimo antigo**. A mensagem é autêntica (a tag confere!) — e ainda assim é uma mentira ("aprove a transferência", de novo). A defesa: cada cliente mantém **dois contadores por peer**, um por direção:

- `seq_send` começa em **0** e vira o `seq_no` de cada envio, incrementando a cada mensagem (e também alimentando o nonce — FASE 6);
- `seq_recv` começa em **-1** e só avança quando chega exatamente o próximo número esperado.

Como cada direção tem seu próprio par (chave, contador), os dois lados podem falar ao mesmo tempo sem colisão.

**Exemplo — contadores do Cliente A:**

| Momento | `seq_send` (A) | `seq_recv` (A) | O que acontece |
|---|---|---|---|
| Após a FASE 5 | 0 | -1 | nada enviado; espera receber `seq_no` 0 |
| A envia a 1ª msg | 0 → 1 | -1 | frame sai com `seq_no` = 0 |
| A recebe a 1ª msg de B | 1 | -1 → 0 | esperava 0 ✓; decifra |
| A envia a 2ª msg | 1 → 2 | 0 | frame sai com `seq_no` = 1 |
| A recebe a 2ª msg de B | 2 | 0 → 1 | esperava 1 ✓; decifra |
| Atacante reenvia o 1º frame de B | 2 | 1 | esperava 2, veio 0 → **rejeitado** |

**Exemplo — contadores do Cliente B (espelho):**

| Momento | `seq_send` (B) | `seq_recv` (B) | O que acontece |
|---|---|---|---|
| Após a FASE 5 | 0 | -1 | espera receber `seq_no` 0 |
| B recebe a 1ª msg de A | 0 | -1 → 0 | esperava 0 ✓; decifra |
| B responde (1ª msg) | 0 → 1 | 0 | frame sai com `seq_no` = 0 |
| B recebe a 2ª msg de A | 1 | 0 → 1 | esperava 1 ✓; decifra |
| Frame com `seq_no` = 3 "do futuro" | 1 | 1 | esperava 2, veio 3 → **rejeitado** |
