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

## Conceitos usados no protocolo

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


### Diffie-Hellman e HKDF

Diffie-Hellman (DH) permite que duas partes obtenham um segredo compartilhado sem
transmiti-lo pela rede. DH puro não autentica o outro lado e, portanto, pode
ser vulnerável a um ataque Man-in-the-Middle (MITM). O handshake RSA-PSS
autentica a resposta inicial do servidor; as chaves públicas dos peers são
distribuídas pelo relay.

HKDF (*HMAC-based Key Derivation Function*) transforma o segredo em
material de chave apropriado, usando um salt e rótulos (`info`) para separar as
chaves de cada direção. Ao contrário do Argon2, que é voltado principalmente
para derivação de chaves a partir de senhas e é deliberadamente custoso em
tempo e memória, HKDF é uma função rápida para derivar chaves de um segredo de
entrada já forte.

### Assinaturas e certificados

Uma assinatura digital é criada com a chave privada do emissor e pode ser
verificada com a chave pública correspondente. Ela comprova integridade e
origem; **não cifra nem torna secreto** o material assinado.

### Entropia

Gerar entropia significa obter aleatoriedade imprevisível. Chaves
criptográficas, salts e bases de IV precisam de fontes aleatórias seguras. Se
um gerador pseudoaleatório usar uma seed fraca ou previsível, valores
criptográficos produzidos por ele podem ser adivinhados.

## Fluxo do protocolo

O fluxo abaixo acompanha as fases do diagrama e a ordem executada pelo código.
Quando a especificação do PDF e a implementação diferem, a diferença é indicada.

### Preparação do servidor

Ao iniciar pela primeira vez, o servidor gera um par RSA e grava o certificado
público em `certs/server.crt` e a chave privada local em `certs/server.key`.
Nos próximos inícios, ambos são reutilizados; a chave privada nunca é enviada
pela rede nem registrada nos logs. O cliente usa `certs/server.crt` como
certificado pinado durante o handshake.

### Fase 1 — Inicialização e registro do cliente

Ao iniciar, cada cliente gera um UUID v4 (`client_id`, 16 bytes) e um par
efêmero X25519. A chave privada (`sk_C`) permanece na memória durante a
execução do cliente; a chave pública (`pk_C`) é serializada em 32 bytes.
Depois, o cliente abre uma conexão TCP assíncrona e envia o frame de registro:

```text
prefixo de tamanho (4B) || client_id (16B) || pk_C (32B)
```

O prefixo é o framing de transporte: um inteiro de 4 bytes em big-endian que
indica o tamanho do payload. Como TCP é um fluxo de bytes sem fronteiras de
mensagens, `recv_frame` lê o prefixo e depois exatamente o tamanho indicado.
Frames maiores que `MAX_FRAME_SIZE` são rejeitados.

### Fase 2 — Handshake autenticado com RSA-PSS

O servidor recebe e valida o frame de registro, gera um `salt_srv` aleatório de
16 bytes e monta o material assinado:

```text
pk_S || pk_C || client_id || salt_srv
```

`pk_S` é a chave pública RSA extraída do certificado. O servidor assina esse
material com RSA-PSS e SHA-256, usando a chave privada mantida em memória, e
responde:

```text
prefixo de tamanho (4B) ||
[tamanho do certificado] || [server.crt] ||
[tamanho da assinatura] || [assinatura RSA-PSS] || [salt_srv]
```

O cliente compara o certificado recebido com `certs/server.crt`, reconstrói o
material com seu próprio `pk_C` e `client_id` e verifica a assinatura com
`pk_S`. Se o certificado ou a assinatura não corresponder, o handshake é
interrompido (*fail-closed*). O certificado é persistente e deve ser
provisionado fora do canal inseguro; na primeira execução do servidor, ele e a
chave privada local são gerados, e os arquivos não são versionados no Git. O
material assinado trafega em claro: a assinatura comprova integridade, mas não
cifra os dados.

O `salt_srv` autentica e identifica essa resposta do handshake. Na derivação
E2E descrita abaixo, ele é usado como salt comum entre os clientes da mesma
execução do servidor.

### Fase 3 — Registro da sessão e anúncios de peers

Depois de responder ao handshake, o servidor entra em `sessions_lock`, envia
ao cliente novo a quantidade de peers online e, em seguida, um frame
administrativo assinado e endereçado para cada peer existente. Também envia um
frame separado, assinado e endereçado, do cliente novo a cada cliente já
conectado. O frame administrativo contém tipo (`JOIN`, `ROTATE` ou `LEAVE`),
`seq_admin`, `announced_id`, `recipient_id`, chave X25519 (ou sentinela de
saída), `salt_srv` e assinatura RSA-PSS.

O contador `seq_admin` é monotônico por processo do servidor, começa em zero e
é alocado sob `sessions_lock`; cada destinatário recebe seu próprio frame e
seu próprio número. O cliente verifica o certificado pinado, o destinatário,
o salt, a assinatura e o contador antes de derivar, substituir ou remover um
peer. Frames administrativos legados sem assinatura são rejeitados.

Um servidor comprometido ainda pode assinar anúncios falsos, pois possui a
chave RSA privada. A assinatura protege contra adulteração ou MITM no canal,
não contra comprometimento do servidor; fingerprints distribuídos fora de
banda ficam como trabalho futuro.

### Fase 4 — Derivação das chaves E2E para cada peer

Após receber a chave pública de outro cliente, cada lado calcula o mesmo
segredo compartilhado:

```text
Cliente A: Z_AB = X25519(sk_A, pk_B)
Cliente B: Z_AB = X25519(sk_B, pk_A)
```

Conceitualmente, isso corresponde a `PK_A = sk_A · G`,
`PK_B = sk_B · G` e `Z_AB = sk_A · (sk_B · G) =
sk_B · (sk_A · G)`. Na implementação, cada lado chama
`private_key.exchange(public_key)`.

O servidor fornece um `salt_srv` aleatório de 16 bytes, autenticado pela
assinatura do handshake, e todos os clientes da mesma execução o usam como
salt comum:

```text
pair_salt = salt_srv
```

Com `Z_AB` e `pair_salt`, HKDF-SHA256 deriva duas chaves de 16 bytes, usando os
rótulos `b"A2B"` e `b"B2A"`. O menor ID do par é A; a chave A é usada no sentido
A→B e a chave B no sentido B→A. Cada cliente escolhe sua chave de envio e
recepção conforme sua posição no par.

Para cada peer, o cliente também gera um `IV_base_send` aleatório de 4 bytes e
inicializa `seq_send=0`, `seq_recv=-1` e `IV_base_recv=None`. O segredo
compartilhado não é mantido na entrada do peer após a derivação. O receptor
aprende a base IV de envio do outro lado a partir do primeiro nonce recebido.

### Fase 5 — Cifragem E2E e relay da mensagem

Ao enviar uma mensagem, o cliente codifica o texto em UTF-8 e cifra com
AES-128-GCM. O nonce tem 12 bytes e é construído com a base IV e a sequência:

```text
nonce = IV_base_send (4B) || seq_send (8B, big-endian)
AAD   = sender_id (16B) || recipient_id (16B) || seq_no (8B)
```

O AAD permanece visível, mas é autenticado pela tag GCM. O payload da
mensagem E2E é:

```text
[nonce (12B)] || [sender_id (16B)] || [recipient_id (16B)] ||
[seq_no (8B)] || [ciphertext || tag GCM (16B)]
```

O frame enviado pela conexão também recebe o prefixo de tamanho de 4 bytes.
`seq_send` só avança depois do envio do frame. O limite de texto claro é 4096
bytes; o maior payload E2E é 4164 bytes, abaixo do limite de transporte de
4200 bytes.

O servidor lê o `recipient_id`, procura a conexão correspondente em `sessions`
e encaminha o payload E2E sem decifrá-lo. Ele atua como relay e não conhece as
chaves simétricas derivadas entre os clientes.

### Fase 6 — Recepção, autenticação e anti-replay

O cliente receptor identifica o remetente pelo ID e exige que ele seja um peer
conhecido. Também exige que a sequência seja exatamente a próxima esperada:

```text
seq_no_recebido == seq_recv + 1
```

Assim, mensagens repetidas, antigas ou com lacunas são rejeitadas. O cliente
decifra com `key_recv`, confere o destinatário esperado e valida a tag GCM.
Também verifica que a base IV recebida não mudou durante a sessão. Uma tag
inválida ou outro erro de validação rejeita o frame; o receptor só atualiza
`IV_base_recv` e `seq_recv` após a validação bem-sucedida e então exibe o texto.

As sequências E2E pertencem ao estado local de cada cliente para cada peer. O
servidor também armazena campos `seq_send` e `seq_recv` na sessão, iniciados
em `0` e `-1`, mas o roteamento e os anúncios de controle atuais não usam esses
campos para autenticar mensagens administrativas.

### Fase 7 — Desconexão

Quando um cliente se desconecta, o servidor remove sua sessão e envia aos
clientes restantes o anúncio de saída com a chave pública sentinela. O cliente
atual não implementa reconexão automática: ao iniciá-lo novamente, um novo ID
e um novo par efêmero X25519 são gerados, e as chaves E2E são derivadas de
novo.

## Exemplo dos contadores por cliente

Cada cliente mantém uma entrada independente para o peer. `seq_send` é o
próximo número a usar para enviar; `seq_recv` é o último número recebido e
aceito.

### Estado que A mantém para B

| Ação | `seq_send` de A para B | `seq_recv` recebido de B |
|---|---:|---:|
| A adiciona B | 0 | -1 |
| A envia mensagem `0` | 1 | -1 |
| A recebe mensagem `0` de B | 1 | 0 |
| A envia mensagem `1` | 2 | 0 |
| A recebe mensagem `1` de B | 2 | 1 |

### Estado que B mantém para A

| Ação | `seq_send` de B para A | `seq_recv` recebido de A |
|---|---:|---:|
| B adiciona A | 0 | -1 |
| B recebe mensagem `0` de A | 0 | 0 |
| B envia mensagem `0` | 1 | 0 |
| B recebe mensagem `1` de A | 1 | 1 |
| B envia mensagem `1` | 2 | 1 |


## Assinatura digital não é criptografia

Quando o servidor assina
`pk_S || pk_C || client_id || salt_srv` com a chave privada RSA mantida em
memória, ele não cifra esses dados. A assinatura permite verificar a
integridade e a correspondência com a chave pública do certificado; o
conteúdo assinado e o certificado trafegam em claro junto dela.

A resposta do handshake contém:

```text
[tamanho do certificado] ||
[server.crt (certificado contendo pk_S)] ||
[tamanho da assinatura] ||
[assinatura RSA-PSS] ||
[salt_srv]
```

O cliente compara o certificado recebido com o arquivo local e verifica a
assinatura RSA-PSS com a chave pública do certificado. Como o certificado é
persistente e provisionado fora do Git, essa validação estabelece o pinning
local do servidor. O mesmo certificado é usado para verificar individualmente
os anúncios administrativos de peers.

## Dicionário de termos e mapeamento com os estudos

| Termo | Significado no projeto |
|---|---|---|
| `client_id` | Identificador UUID v4 de 16 bytes do cliente. | 
| `sk` / `pk` | Chave privada (`sk`) e chave pública (`pk`). | 
| `X25519` | Curva usada para o Diffie-Hellman efêmero. |
| `Z_AB` | Segredo bruto compartilhado calculado via ECDH entre A e B. |
| `salt_srv` | Salt aleatório gerado pelo servidor durante o handshake. |
| `HKDF` | Função para derivar chaves de `Z_AB`. |
| `server.crt` | Certificado autoassinado persistente, provisionado fora do Git; contém a chave pública. |
| `RSA-PSS` | Algoritmo de assinatura usado no handshake do servidor. | 
| `AES-128-GCM` | Cifra AEAD que fornece confidencialidade e autenticação. |
| `AAD` | Dados autenticados, mas não cifrados: remetente, destinatário e sequência. | 
| `seq_no` | Contador por direção usado para nonce, ordenação e anti-replay. | 


## Observações sobre X25519 e ECDH

1. Cada parte gera uma chave privada e a chave pública correspondente:

   ```text
   PK_A = sk_A · G
   PK_B = sk_B · G
   ```

2. A troca de segredo pode ser representada conceitualmente como:

   ```text
   Segredo_A = sk_A · (sk_B · G)
   Segredo_B = sk_B · (sk_A · G)
   ```

   Na implementação X25519, cada lado chama `.exchange()` com sua chave
   privada e a chave pública do peer. Ambos obtêm o mesmo `Z_AB`.

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
5. **Assina** esse material com **RSA-PSS + SHA-256**, usando sua chave privada.
6. **Responde ao cliente:** `(certificado, assinatura, salt)`.

Por que assinar o material inteiro (e não só o salt)? Porque a assinatura "gruda" as peças: ela vale para **aquela** `pk_a`, **aquele** `id_a` e **aquele** salt, naquela ordem. Trocar qualquer byte invalida a verificação na FASE 3.

### Conceito: assinatura digital

Com RSA-PSS, o servidor usa sua chave **privada** para gerar uma assinatura
associada ao material do handshake. O cliente usa a
chave **pública** correspondente para verificar se a assinatura confere com
esse material.

**Assinatura não é criptografia:** ela não esconde o material assinado; neste
handshake, os dados e a assinatura trafegam em claro.

### Conceito: salt e entropia

**Salt** é um valor aleatório usado como tempero de derivação, para que o mesmo material produza resultados diferentes em sessões diferentes. **Entropia** é a imprevisibilidade da aleatoriedade — e toda a segurança do protocolo repousa sobre ela.

## FASE 3: Validação do handshake (Cliente)


1. **Compara o certificado:** compara o `cert` recebido com o `certs/server.crt` pinado localmente. Diferente → **conexão encerrada**.
2. **Extrai `pk_S`** do certificado.
3. **Remonta o material:** `pk_S || pk_a || id_a || salt` 
4. **Verifica a assinatura** RSA-PSS com `pk_S`. Inválida → **conexão encerrada**.

## FASE 4: Registro na sessão e anúncio dos peers (Servidor)

Com o handshake validado, o servidor integra o cliente à rede:

1. Sob a `sessions_lock` (`asyncio.Lock`) registra a sessão
2. Envia o número de peers online* e os dados de cada um.
3. A partir daqui o Cliente A sabe quem está online e com quais chaves públicas.

Os anúncios de peers também são assinados pelo servidor e verificados com o
certificado pinado. Isso autentica a origem do anúncio contra atacantes de rede;
não protege contra um servidor comprometido, que possui a chave privada RSA.

## FASE 5: Derivação das chaves E2E (Cliente A e Cliente B)

Cada cliente, ao conhecer um peer, executa independentemente, e chegando ao mesmo resultado:

1. **Calcula o segredo compartilhado:** `Z = sk.exchange(pk_do_peer)` com X25519. O Cliente A usa `sk_a` com `pk_b`; o Cliente B usa `sk_b` com `pk_a`. Ambos obtêm **os mesmos 32 bytes de `Z`** — que nunca trafegaram na rede.
2. **Usa o salt do servidor:** `pair_salt = salt_srv` — aleatório por execução, autenticado no handshake e igual nos dois lados.
3. **Deriva as duas chaves de direção com HKDF-SHA256:**
   - `key_A2B = HKDF(salt=pair_salt, info=b"A2B", length=16)`
   - `key_B2A = HKDF(salt=pair_salt, info=b"B2A", length=16)`
4. **Define o papel pelo menor id:** se meu id < id do peer, sou o "A" deste par → `key_send = key_A2B` e `key_recv = key_B2A`; senão, o contrário. Cada direção usa **uma chave diferente** (full-duplex seguro).
5. **Gera o `IV_base_send`:** 4 bytes aleatórios — a base dos nonces desta direção (FASE 6).
6. **Descarta `Z`:** o segredo bruto some da memória; só as chaves derivadas permanecem.
7. **Registra o peer:** `peers[id_peer] = {key_send, key_recv, IV_base_send, seq_send = 0, seq_recv = -1}`.

O enunciado do trabalho especifica, e a implementação aplica, o uso do
`salt_srv` e dos rótulos `A2B`/`B2A`.

Quando um peer reconecta com o mesmo `client_id`, um anúncio `ROTATE` assinado
com a nova chave substitui o estado anterior e reinicia os contadores E2E dessa
sessão. O cliente mantém `last_seq` administrativo por
`(salt_srv, announced_id, recipient_id)` entre reconexões do mesmo processo,
rejeitando números iguais ou menores.

### Conceito: Diffie–Hellman em curvas elípticas (ECDH)

O problema que o DH resolve: **como duas partes que nunca se falaram criam um segredo comum, olhando apenas mensagens públicas?** A resposta é a aritmética da troca: A calcula `Z = sk_a × pk_b` e B calcula `Z = sk_b × pk_a` — pelas propriedades da curva, os resultados são **iguais**, mas um observador que vê apenas `pk_a` e `pk_b` não consegue computar `Z` (problema do logaritmo discreto elíptico). O X25519 é a versão moderna e padronizada do ECDH sobre a curva Curve25519: chaves de 32 bytes, rápida e desenhada para resistir a ataques de side-channel de tempo.

### Conceito: HKDF (função de derivação de chaves)

O `Z` bruto não deve virar chave de cifra diretamente (pode ter vieses estruturais). O **HKDF** (HMAC-based Key Derivation Function, RFC 5869) o transforma em chaves de uso específico em duas etapas: **extract** (comprime a entropia de `Z` junto com o salt) e **expand** (expande para o tamanho desejado, temperado pelo `info`). O `info` — aqui os rótulos `b"A2B"` e `b"B2A"` — **separa os domínios**: derivar com rótulos diferentes produz chaves totalmente independentes mesmo com a mesma entrada. É por isso que uma direção não consegue decifrar o tráfego da outra.

### Observações sobre X25519 e ECDH

- **Por que curvas elípticas?** Chaves curtas com segurança alta: 256 bits de curva equivalem a aproximadamente 3072 bits de RSA — e o X25519 usa chaves de apenas 32 bytes.
- **Por que chaves efêmeras?** O par nasce no boot (FASE 1) e morre com a execução do cliente. Reiniciou, chaves novas — e, com UUIDs novos, salt do par e chaves de sessão também novos.
- **`exchange()` é o DH:** `private_key.exchange(public_key)` devolve exatamente o segredo compartilhado de 32 bytes; a operação é simétrica — qualquer dos dois pares calcula o mesmo `Z`.
- **`Z` é descartado de propósito** (passo 6): nada além das chaves HKDF deve depender dele. Menos segredos vivos em memória, menor superfície de vazamento.

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
