# WhatsUp - Sistema de Mensageria Multi-Cliente (E2E)

## Visão geral

O WhatsUp é uma aplicação de mensageria com criptografia ponta a ponta (E2E). Clientes trocam mensagens cifradas, 
enquanto o servidor atua como relay: ele gerencia conexões e encaminha frames, mas não
decifra o conteúdo das mensagens.

![](/public/whatsup-logo.png)

### Garantias

1. **Confidencialidade:** AES-128-GCM (cifragem simétrica) cifra o conteúdo das mensagens e somente o alvo pode decifrar.
2. **Integridade:** a tag de autenticação do AES-GCM detecta adulterações;
3. **Autenticidade:** o servidor é autenticado pelos clientes.
4. **Proteção contra replay:** contadores de sequência por direção rejeitam mensagens repetidas ou "futuras".


## Navegação

- [Visão geral e garantias](#visao-geral)
- [Execução](#execucao)
- [Como acompanhar as fases no código](#como-acompanhar-as-fases-no-codigo)
- [Diagrama de sequência](#diagrama-de-sequencia)
- [FASE 0: Credenciais do servidor](#fase-0-credenciais-servidor)
- [FASE 1: Registro do cliente](#fase-1-registro-cliente)
- [FASE 2: Handshake do servidor](#fase-2-handshake-servidor)
- [FASE 3: Validação do handshake](#fase-3-validacao-do-handshake-cliente)
- [FASE 4: Registro e anúncio de peers](#fase-4-registro-na-sessao-e-anuncio-dos-peers-servidor)
- [FASE 5: Derivação das chaves E2E](#fase-5-derivacao-das-chaves-e2e)
- [FASE 6: Cifragem E2E com AES-128-GCM](#fase-6-cifragem-e2e-com-aes-128-gcm)
- [FASE 7: Recepção, anti-replay e decifragem](#fase-7-recepcao-anti-replay-e-decifragem-cliente-b)

---

## Execução


```bash
python3 -m pip install cryptography
```
```bash
python3 server.py
```
```bash
python3 -m unittest discover -s tests
```
---

## Como acompanhar as fases no código

As fases do protocolo estão implementadas em mais de um arquivo. Use este mapa.

| Fase | Caminho no código |
|---|---|
| 0 - Credenciais do servidor | `server.main()` chama `generate_server_credentials()`|
| 1 - Registro do cliente | `client.main()` gera o ID e o par X25519, monta o registro e chama `send_frame()` em `protocol/framing.py`. |
| 2 - Handshake do servidor | `server.handle_client()` chama `server.registration()`, que usa `create_server_handshake_response()` em `protocol/handshake.py`. |
| 3 - Validação do handshake | `client.main()` verifica a resposta com `verify_server_handshake_response()` em `protocol/handshake.py`. |
| 4 - Anúncio de peers | `server.registration()` envia anúncios assinados; `client.apply_admin_frame()` valida com `verify_admin_frame()` em `protocol/admin.py`. |
| 5 - Derivação das chaves E2E | `client.apply_admin_frame()` chama `client.add_peer()`, que usa `derive_e2e_keys()` em `protocol/crypto.py`. |
| 6 - Envio de mensagem | `client.send_chat_message()` chama `encrypt_e2e_message()` e depois `send_frame()`. |
| 7 - Recepção de mensagem | `client.receive_messages()` chama `validate_and_decrypt_frame()` em `protocol/crypto.py`. |

`client_terminal.py` contém a interface curses e o tratamento das teclas. Ela
recebe estado e a função de envio do `client.py`; assim, a apresentação fica
separada da lógica de protocolo e criptografia.

## Diagrama de sequência


![Diagrama de sequência do protocolo WhatsUp](/public/DiagramaDeSequencia-WhatsUP.svg)

## FASE 0: Credenciais (Servidor)

O WhatsUp usa dois tipos de criptografia:

- **Assimétrica:** usa um par de chaves pública e privada. Nesta fase, o
  servidor usa RSA. X25519 também usa chaves
  assimétricas, mas para os peers derivarem um segredo compartilhado na FASE 5.
- **Simétrica:** usa a mesma chave secreta para cifrar e decifrar. 

![](/public/Criptografias.png)

O `server.crt` é um certificado X.509 autoassinado que contém a chave pública RSA
do servidor e sua identidade. É público e pode ser compartilhado.
A chave privada correspondente é usada para assinar o handshake e não deve ser compartilhada.

Durante cada inicialização, `server.py` chama
`generate_server_credentials()`, que gera um novo par RSA e grava o certificado
público em `certs/server.crt`. A chave privada fica apenas em memória.

O cliente compara o certificado recebido no handshake com `certs/server.crt` e
usa a chave pública nele contida para verificar a assinatura RSA-PSS. 

## FASE 1: Registro (Cliente)

Quando um cliente é iniciado:

1. **Gera seu id:** um UUID
2. **Gera par de chaves X25519:** `sk_a` (privada) e `pk_a` (pública). São efêmeras: nascem e morrem com esta execução do cliente.
3. Conecta ao servidor.
4. **Envia o frame de registro:** `Pre(4B) || id_a(16B) || pk_a(32B)`. 
- **Prefixo:** informa, em 4 bytes, o tamanho do payload que vem depois dele.

**FRAME**: O TCP é um fluxo de bytes sem fronteiras de mensagem. Por isso todo frame começa com `Pre`, um prefixo de **4 bytes big-endian** declarando o tamanho do payload. 


## FASE 2: Handshake (Servidor)

Assim que o registro chega, o servidor responde provando quem é:

1. Recebe `id_a` e `pk_a`.
2. **Gera um `salt` aleatório** para esta sessão.
4. **Monta o material do handshake:** `pk_S || pk_a || id_a || salt`.
5. **Calcula** `H = SHA256(material)` e assina `H` com **RSA-PSS**, usando sua chave privada.
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

**Salt**: valor aleatório usado como "tempero". Para que o mesmo material produza resultados diferentes em sessões diferentes. 

## FASE 3: Validação do handshake (Cliente)

1. **Compara o certificado:** compara o `cert` recebido com o `certs/server.crt` pinado localmente.
2. **Extrai `pk_S`** do certificado.
3. **Remonta o material:** `pk_S || pk_a || id_a || salt` 
4. **Verifica a assinatura** RSA-PSS com `pk_S`. Inválida → **conexão encerrada**.

## FASE 4: Registro na sessão e anúncio dos peers (Servidor)

Com o handshake validado, o servidor integra o cliente à rede:

1. Sob a `sessions_lock` (`asyncio.Lock`) registra a sessão
2. Envia o número de peers online e os dados de cada um.
3. A partir daqui o Cliente A sabe quem está online e com quais chaves públicas.

Os anúncios de peers também são assinados pelo servidor e verificados com o
certificado pinado.

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

![](/public/diagramaChaves.png)


## FASE 6: Cifragem E2E com AES-128-GCM

Com as chaves key_send e key_recv em mãos, o cliente A escreve para B:

1. **Constrói o nonce:** `nonce = IV_base_send(4B) || seq_send(8B, big-endian)`. O contador embutido garante **nonce nunca repetido**.
2. **Constrói os dados associados AAD:** `sender_id(16B) || recipient_id(16B) || seq_send(8B)`
3. **Cifra:** `AESGCM(key_send).encrypt(nonce, plaintext, aad)` → ciphertext com a **tag de 16 B** anexada.
4. **Envia o frame E2E** ao servidor, endereçado a `id_b`. O servidor **repassa intacto**: não pode ler (não tem a chave) nem adulterar (a tag pega na FASE 7).

### Conceito: AES-GCM e AEAD

O **AES-128-GCM** é um algoritmo de criotigrafia assimétrica **AEAD** (Authenticated Encryption with Associated Data). A tag é o "selo": decifrar com qualquer byte alterado — do ciphertext, do nonce ou do AAD — falha com `InvalidTag`.

**AEAD:**
  - **Dados associados (AAD)**: são informações que não são criptografadas, mas são incluídas no cálculo para gerar a tag de autenticação.
  - **Tag de autenticação**: é um código de verificação para garantir integridade.
  - **Nonce**: valor usado pelo AES-GCM. Não é secreto, mas precisa ser único para cada mensagem.

![](/public/frameE2E.png)


## FASE 7: Recepção, anti-replay e decifragem (Cliente B)

O cliente B recebe um frame E2E e executa, nesta ordem:

1. **Validação anti-replay:** exige `seq_no == seq_recv + 1`.
2. **Decifra:** `AESGCM(key_recv).decrypt(nonce, ciphertext+tag, aad)`.
3. **`InvalidTag` → mensagem descartada.
4. **Atualiza o contador:** `seq_recv = seq_no`.

A ordem importa: o anti-replay vem antes da decifragem, para que frames repetidos nem cheguem a decifragem.

### Conceito: ataque de replay e os contadores por direção

**Replay** é o ataque em que o adversário **retransmite um frame legítimo antigo**. A mensagem é autêntica (a tag confere) — e ainda assim é uma mentira ("aprove a transferência", de novo).

Para se defender cada cliente mantém **dois contadores por peer**:
- `seq_send` começa em **0**, incrementando a cada mensagem.
- `seq_recv` começa em **-1** e só avança quando chega exatamente o próximo número esperado.

**Exemplo — contadores do Cliente A:**

| Momento | `seq_send` (A) | `seq_recv` (A) | O que acontece |
|---|---|---|---|
| Após a FASE 5 | 0 | -1 | espera receber `seq_no` 0 |
| ENVIA | 0 → 1 | -1 | frame sai com `seq_no` = 0 |
| RECEBE | 1 | -1 → 0 | esperava 0 ✓; decifra |
| ENVIA | 1 → 2 | 0 | frame sai com `seq_no` = 1 |
| RECEBE | 2 | 0 → 1 | esperava 1 ✓; decifra |
| Atacante reenvia o 1º frame de B | 2 | 1 | esperava 2, veio 0 → **rejeitado** |

**Exemplo — contadores do Cliente B (espelho):**

| Momento | `seq_send` (B) | `seq_recv` (B) | O que acontece |
|---|---|---|---|
| Após a FASE 5 | 0 | -1 | espera receber `seq_no` 0 |
| RECEBE | 0 | -1 → 0 | esperava 0 ✓; decifra |
| ENVIA | 0 → 1 | 0 | frame sai com `seq_no` = 0 |
| RECEBE | 1 | 0 → 1 | esperava 1 ✓; decifra |
| Frame com `seq_no` = 3 "do futuro" | 1 | 1 | esperava 2, veio 3 → **rejeitado** |
