**Sistema de Mensageria Segura Multi-Cliente (Python)** 

> 1. Execute as etapas **em ordem sequencial**
> 2. Marque as tarefas com os checkboxes ( `- [ ]` → `- [x]` )

### Requisitos

| Requisito do enunciado | Mecanismo definido no TP | Etapas do plano |
|---|---|---|
| Confidencialidade | AES-128-GCM (AEAD) | 6 |
| Integridade | Tag GCM + AAD (sender_id ‖ recipient_id ‖ seq_no) | 6, 7 |
| Autenticidade do servidor | RSA-PSS(SHA-256) sobre o handshake + `server.crt` pinado | 4 |
| Sigilo perfeito (forward secrecy) | ECDHE com X25519 (chaves efêmeras) | 3, 5 |
| Anti-replay | `seq_no` monotônico por direção | 6, 7 |
| Servidor "cego" | Relay sem chaves simétricas E2E | 5, 8 |

---

## 1. Visão geral — o que você vai construir

Um servidor e 2 clientes. O servidor é um **relay cego**: ele conecta as pontas e distribui chaves públicas, mas não consegue decifrar o tráfego entre clientes, porque nunca detém as chaves simétricas E2E. Toda a comunicação ocorre sobre uma conexão TCP com o servidor.

O protocolo tem **dois planos**:

- **Plano de controle** (cliente ↔ servidor): handshake com autenticação do servidor, registro de `client_id` + chave pública X25519, distribuição de chaves públicas entre pares e mensagens administrativas (confirmações, avisos de entrada/saída, erros).
- **Plano de dados** (cliente ↔ cliente, via relay): frames E2E cifrados com AES-128-GCM, usando chaves que só os dois clientes conhecem.

![](image.png)


### Onde a complexidade realmente mora

Três pontos concentram quase todos os bugs desse projeto, e o plano os persegue de frente: 
1. **framing** — TCP é um fluxo de bytes sem fronteiras de mensagem, então quem não fizer o prefixo de comprimento direito vai ver mensagens coladas ou truncadas; 
2. **disciplina de direção das chaves** — decidir de forma determinística quem é "A" e quem é "B" em cada par, para os dois lados derivarem a mesma chave de envio/recebimento; 
3. **contabilidade de nonce/seq** — contadores separados por direção, inicializados de forma consistente nos dois lados. Nada disso é difícil isoladamente; o perigo é misturar tudo de uma vez. Por isso o plano separa.


---

## 2. Mapa das suas anotações → TP3

Você já estudou **tudo** que o TP usa — o projeto é a "montagem". Esta tabela é o seu índice de revisão:

| Sua anotação | Conceito que você já estudou | Onde entra no TP3 | Etapa |
|---|---|---|---|
| [[7_Criptografia]] | Simétrica × assimétrica; cifra de bloco × fluxo; "criptografia garante **só** confidencialidade" | AES-128-GCM é a parte simétrica (tráfego); X25519 e RSA são as assimétricas (estabelecimento); como a cripto sozinha não autentica, o TP soma AAD + tag + assinatura RSA | 0, 3, 4, 6 |
| [[8_Função Hash e Mac]] | Hash unidirecional e resistência a colisão; HMAC (ipad/opad) como "checksum com chave" | SHA-256 do material assinado no handshake; HMAC é o bloco construtivo do HKDF; fingerprints de chave nos logs (permitidos pela política) | 3, 4, 5 |
| [[9_Troca de chaves privadas]] | Diffie-Hellman (analogia das tintas); **problema dos dois métodos: autenticação → MITM** | ECDHE é DH feito em curva elíptica (X25519 = mesmo conceito, outra matemática); o MITM apontado na aula é exatamente o que a Etapa 4 elimina | 3, 4, 5 |
| [[10_Key Derivation Function]] | KDF, salt, iteração; Argon2 usa memória para travar GPU | Diferença crucial: **HKDF é rápido** (deriva chaves de material já de alta entropia, o Z do ECDH); Argon2 é lento de propósito (senhas fracas). O `salt_srv` aqui é contexto da sessão, não proteção de senha | 5 |
| [[11_Assinatura e certificado digital]] | Assinatura = assinar só o hash com a sk; certificado = vínculo "identidade ↔ chave" assinado **uma vez**; CA/PKI | `server.crt` autoassinado **pinado** no cliente (a "CA caseira"); RSA-PSS(SHA-256) no handshake — assinatura acontece 1× por conexão, não por mensagem | 4 |
| [[12_Protocolos de Segurança]] | EtM × MtE × E&M; AEAD; padding oracle; forgery | AES-GCM **é** um AEAD: a composição segura (EtM) já vem embutida; GCM não tem padding → padding oracle não se aplica; a tag rejeita forgery antes de qualquer decifragem | 6, 7, 9 |

> [!tip] Ordem de revisão sugerida
> Releia [[11_Assinatura e certificado digital]] e [[9_Troca de chaves privadas]] antes da **Etapa 4** (é o pico teórico do plano), [[10_Key Derivation Function]] e [[8_Função Hash e Mac]] antes da **Etapa 5**, e [[12_Protocolos de Segurança]] antes da **Etapa 6**. A [[7_Criptografia]] é transversal a tudo.

---
## 3. Etapas de desenvolvimento

### Etapa 0 — Ambiente e biblioteca `cryptography`

> [!summary] Ficha rápida
> **Objetivo:** ambiente Python isolado com a biblioteca criptográfica instalada e um "ping" manual na API.

**O que você está construindo e por quê.** Todo o trabalho criptográfico será feito com a biblioteca `cryptography`. Ela tem duas camadas: APIs de alto nível (tipo Fernet, que esconde os detalhes) e o módulo `hazmat` (*hazardous materials* — "materiais perigosos"), que expõe primitivas cruas como X25519, RSA-PSS e AES-GCM. O TP exige `hazmat` de propósito: você precisa controlar explicitamente nonce, AAD e derivação de chaves — justamente os detalhes que as APIs convenientes escondem. É por isso que o nome já avisa: com controle vem responsabilidade (usar nonce repetido, por exemplo, quebra o GCM silenciosamente).

**Tarefas:**
- [x] Criar a pasta do projeto (sugestão de layout no **Anexo A**) e iniciar controle de versão (`git init`).
- [x] Criar ambiente virtual (`venv`) e instalar a biblioteca `cryptography` via `pip`.
- [x] Reler o enunciado do TP com o mapa da seção 3 aberto ao lado, sublinhando onde cada aula aparece.

---

### Etapa 1 — Rede: TCP + framing (a fundação)

> [!summary] Ficha rápida
> **Objetivo:** servidor que aceita várias conexões simultâneas + cliente, trocando **frames** com prefixo de comprimento — ainda sem criptografia.
> **Tempo estimado:** ~5 h · **Depende de:** Etapa 0 · **Aulas que sustentam:** nenhuma ainda — é a base de sistemas distribuídos.

**O que você está construindo e por quê.** TCP é um **fluxo de bytes**, não uma fila de mensagens: se você enviar dois frames de 20 bytes, o recebedor pode receber 13 bytes, depois 27 — e o TCP acha isso ótimo. Como todos os frames do TP (handshake, E2E, administrativos) têm tamanhos variáveis, você precisa de **framing**: cada frame é precedido por **4 bytes em big-endian** (network byte order) indicando o tamanho do payload que vem em seguida. O recebedor lê os 4 bytes, sabe quantos bytes faltam e lê exatamente esse tanto, em loop, até completar. O enunciado exige isso explicitamente, e a rubrica testa: *framing inválido → desconexão segura*.

Para concorrência, o PDF do professor entrega a resposta: a tabela `sessions` do servidor guarda um `StreamWriter` — essa é a classe da **`asyncio`** (biblioteca padrão). Use `asyncio` (com `start_server` e streams); `threading` também resolveria, mas você desviaria da estrutura de dados que o enunciado define e ganharia dores de cabeça com travas.

**O que estudar antes:**
- Docs oficiais do Python: `asyncio` → seção **Streams** (`start_server`, `StreamReader.readexactly`, `StreamWriter.write` + `drain`, `wait_closed`).
- Conceito de *coroutine* / `async`/`await` — tutorial "Async IO in Python: A Complete Walkthrough" (Real Python), só as partes de conceito e streams.
- Entender por que `readexactly(n)` é a ferramenta perfeita para framing (só retorna quando tiver os n bytes; levanta `IncompleteReadError` se a conexão morrer no meio).

**Tarefas:**
- [ ] Servidor: aceitar N conexões simultâneas com `asyncio.start_server`; para cada conexão, gerar uma *task* de atendimento.
- [ ] Implementar (dois lados, mesma lógica) `send_frame(payload)` e `recv_frame()`: prefixo de 4 bytes big-endian + payload — referências: `struct` com formato `>I` **ou** `int.to_bytes(length=4, byteorder="big")` / `int.from_bytes(..., "big")`; leitura com `readexactly`.
- [ ] Cliente conecta, envia um payload de teste, servidor **ecoa** de volta (teste temporário — o eco some nas etapas seguintes).
- [ ] Teste de estresse do framing: enviar um payload de ~4000 bytes e conferir que chega íntegro (tamanho e conteúdo) — é aqui que implementações ingênuas quebram.
- [ ] Tratamento de erro: conexão cai no meio de um frame → `IncompleteReadError` → log limpo e encerramento da task, **sem traceback feio e sem derrubar as outras conexões**.
- [ ] Definir um limite máximo de frame aceito (sugestão: ~4,2 KB — ver Etapa 6) e rejeitar prefixos maiores como erro de protocolo (isso mata ataques de "length prefix gigante" que estourariam memória).

**Critério de concluído:**
- [ ] Dois terminais (servidor + cliente) trocam frames nos dois sentidos sem corrupção, incluindo o de ~4000 bytes.
- [ ] Matar o cliente com Ctrl+C fecha a conexão sem crash do servidor; abrir 3 clientes simultâneos não confunde os fluxos.

> [!warning] Armadilhas
> 1. **Nunca** use `\n` ou outro caractere como delimitador (o conteúdo cifrado é binário e pode conter qualquer byte).
> 2. **Nunca** assuma que uma única leitura devolve o frame inteiro — é exatamente por isso que existe `readexactly`/loop.
> 3. Big-endian nos 4 bytes **e** em todo campo numérico do protocolo (`seq_no` etc.). Escolha uma abordagem (`struct` ou `to_bytes`) e use a mesma nos dois lados.

---

### Etapa 2 — Identidade: `client_id` UUID v4

> [!summary] Ficha rápida
> **Objetivo:** cada cliente com identidade única de 16 bytes, pronta para trafegar binária e para log textual.
> **Tempo estimado:** ~1 h · **Depende de:** Etapa 1

**O que você está construindo e por quê.** O TP define `client_id` como **UUID v4 binário de 16 bytes** (network byte order). UUID v4 é um identificador gerado a partir de ~122 bits aleatórios — a chance de dois clientes gerarem o mesmo é desprezível, o que elimina a necessidade de um "central de nomes". Na rede ele trafega como 16 bytes crus (barato e de tamanho fixo); para debug você usa a representação textual com hífens **fora** do protocolo (logs, tela). Essa dualidade binário-no-wire/texto-no-log vai se repetir em tudo: chaves, salt, nonce.

**O que estudar antes:**
- Docs oficiais do módulo `uuid` (foco em `uuid4()` e no atributo `.bytes`).

**Tarefas:**
- [ ] No boot do cliente, gerar `client_id` uma única vez por processo (conexões subsequentes do mesmo processo reutilizam o id — e na reconexão o handshake será refeito, ver Etapa 8).
- [ ] Criar helpers de apresentação para logs: id de 16 bytes → string hex/textual (referência: `UUID(bytes=...)` e `.hex`).
- [ ] Incluir o `client_id` no frame de registro que o cliente já envia ao servidor da Etapa 1 (substituindo o eco temporário por "recebi registro de X").

**Critério de concluído:**
- [ ] Dois clientes em execução simultânea têm ids distintos; o log do servidor mostra ambos de forma legível e estável.

---
### Etapa 3 — Chaves X25519 e registro no servidor

> [!summary] Ficha rápida
> **Objetivo:** cada cliente gera seu par efêmero X25519 e se registra; o servidor mantém a tabela `sessions` com `client_id → pk`.
> **Tempo estimado:** ~3 h · **Depende de:** Etapa 2 · **Aulas que sustentam:** [[7_Criptografia]] (assimétrica/ECC), [[9_Troca de chaves privadas]] (Diffie-Hellman)

**O que você está construindo e por quê.** Aqui começa a criptografia de verdade — e ela é literalmente a Aula 9 trocando de matemática. No DH clássico das anotações, Alice envia `A = g^a mod p`; no X25519 (DH sobre curva elíptica), Alice envia `pk_A` de 32 bytes. A propriedade é a mesma: quem conhece só as chaves **públicas** não consegue calcular o segredo; quem conhece a própria chave **privada** + a pública do outro, consegue. Dois detalhes de nomenclatura do enunciado: o par é **efêmero** (gerado a cada execução/conexão — é o "E" de ECDHE, e é ele que compra o sigilo perfeito) e a chave pública trafega como **32 bytes crus** (o TP proíbe PEM/DER no wire, por simplicidade e interoperabilidade). `sk` nunca sai da memória do dono; `pk` é público e viaja feliz.

Nesta etapa o servidor só **registra** (ainda não autentica nada — isso é a Etapa 4). A tabela `sessions` nasce aqui com a forma do enunciado: `client_id → {writer, public_key, seq_send: 0, seq_recv: -1, salt}`.

**O que estudar antes:**
- Releia [[9_Troca de chaves privadas]] (a analogia das tintas É o ECDH) e a parte de ECC em [[7_Criptografia]].
- Docs da `cryptography`: seção **X25519** (`X25519PrivateKey.generate()`, `.exchange()`, `X25519PublicKey.from_public_bytes()`).
- RFC 7748 §1 (só a introdução, se quiser ver o formal).

**Tarefas:**
- [ ] Cliente: no boot, gerar o par efêmero (`X25519PrivateKey.generate()`); serializar a pública com `Encoding.Raw` + `PublicFormat.Raw` (32 bytes) e manter a privada só em memória.
- [ ] Frame de registro: `client_id` (16B) + `pk_C` (32B), já usando o framing da Etapa 1.
- [ ] Servidor: registrar a entrada na tabela `sessions` (inicialize `seq_send = 0` e `seq_recv = -1` conforme o enunciado; `salt` fica vazio até o handshake da Etapa 4).
- [ ] Log de registro usando **fingerprint** da chave: `SHA-256(pk_C)` truncado em ~8 bytes hexadecimais — referência: `cryptography.hazmat.primitives.hashes` → `Hash(SHA256())`. (Logar fingerprint é permitido pela política de logs e é seguro por causa da unidirecionalidade do hash — [[8_Função Hash e Mac]].)
- [ ] Decisão de projeto → **Anexo B (D-estutura)**: registrar aqui que chaves são logadas só como fingerprint, nunca inteiras.

**Critério de concluído:**
- [ ] Dois clientes conectam e o servidor exibe duas entradas em `sessions`, cada uma com id + fingerprint da chave.
- [ ] Nenhum log imprime a chave privada ou a pública inteira.

> [!tip] Para a apresentação
> Guarde essa frase: *"X25519 é o Diffie-Hellman da Aula 9 implementado sobre curvas elípticas, com par gerado por sessão — por isso o sistema tem forward secrecy antes mesmo de cifrar a primeira mensagem."*

---

### Etapa 4 — Autenticação do servidor: RSA + certificado autoassinado + RSA-PSS

> [!summary] Ficha rápida
> **Objetivo:** handshake autenticado — o cliente tem prova criptográfica de que fala com O servidor (e não com um MITM), e de que o servidor registrou a chave dele exatamente como ele enviou.
> **Tempo estimado:** ~6 h · **Depende de:** Etapa 3 · **Aulas que sustentam:** [[11_Assinatura e certificado digital]] (a aula mais importante daqui), [[7_Criptografia]] (RSA), [[9_Troca de chaves privadas]] (o problema do MITM)

**O que você está construindo e por quê.** Volte à aula 9: *nenhum método de troca de chaves puro oferece autenticação → MITM possível*. E à aula 11: *a assinatura prova "quem tem a chave privada correspondente assinou", não "Bob assinou" — a ligação identidade↔chave vem do certificado*. O TP resolve os dois com uma construção elegante em miniatura:

1. O servidor tem um par RSA e um **certificado autoassinado** `server.crt`, **pinado** nos clientes (distribuído fora do canal, no seu caso: embutido/presente no projeto). O pinning substitui a CA: como a relação é fixa e conhecida, a "prova autocontida" da aula 11 vira "eu só falo com o dono DESTE certificado". Autoassinado + pinning é o padrão de sistemas fechados (é um mini-PKI, como sua anotação descreve: a CA assina UMA vez o vínculo — aqui, você mesmo assina o vínculo na hora de gerar o certificado).
2. No handshake, o servidor gera o `salt_srv` (16B) e assina com **RSA-PSS(SHA-256)** o digest `H = SHA256(pk_S ‖ pk_C ‖ client_id ‖ salt_srv)`. Note o que está dentro do hash: a chave pública **do servidor** (prova posse da sk RSA), a chave pública **do cliente** e seu id (o servidor atesta: "registrei EXATAMENTE esta chave para ESTE cliente") e o salt (amarra a assinatura a esta sessão específica). Um MITM que interceptar o registro e trocar `pk_C` quebra a verificação no cliente.
3. A assinatura acontece **uma vez por conexão** (no handshake) — exatamente o ditado da sua aula: *certificado = uma vez por relação; assinatura = a cada mensagem*. Aqui a "mensagem assinada" é o handshake inteiro.

**O que estudar antes:**
- Releia [[11_Assinatura e certificado digital]] inteira e [[9_Troca de chaves privadas]] (seção do problema da autenticação).
- Docs da `cryptography`: **RSA** (`generate_private_key`, `sign`, `verify`), **padding.PSS** (com `MGF1(SHA256)`), **x509** (`CertificateBuilder`, `load_pem_x509_certificate`), **serialization** (`load_pem_private_key`, `Encoding.PEM`), exceção `InvalidSignature`.
- Para gerar o certificado autoassinado: ou via `CertificateBuilder` da biblioteca, ou via CLI `openssl req` (busque "openssl self-signed certificate x509" — comando único, feito uma vez, fora do código de rede).

**Tarefas:**
- [ ] Ferramenta one-off (`tools/gen_cert`): gerar par RSA ≥ 2048 bits (sugestão: 3072) + `server.crt` autoassinado (subject = issuer = CN tp3-server). O par RSA é **de longo prazo** — oposto do par X25519 efêmero; guarde `server.key` fora do controle de versão (`.gitignore`).
- [ ] Servidor: no boot, carregar `server.key` + `server.crt`.
- [ ] Cliente: no boot, carregar o `server.crt` **pinado** e extrair `pk_S` dele.
- [ ] Handshake (servidor): gerar `salt_srv = secrets.token_bytes(16)` (referência: módulo `secrets`, ou `os.urandom`); montar o material `pk_S ‖ pk_C ‖ client_id ‖ salt_srv` (todos cru, na **ordem exata do enunciado**); assinar com RSA-PSS(SHA-256); responder com `server.crt + assinatura + salt_srv`.
- [ ] Handshake (cliente): conferir que o certificado recebido == o pinado; extrair `pk_S`; remontar o material na mesma ordem com seus próprios valores; `verify(...)` → em caso de `InvalidSignature`, **desconectar imediatamente** e logar o motivo (motivo é logável; o material, não).
- [ ] Teste negativo (temporário): corromper 1 byte da assinatura antes de verificar → handshake deve falhar. Depois corromper 1 byte do salt → também deve falhar (o hash muda).
- [ ] Documentar no README a ordem exata dos campos do material assinado (isso É o contrato do protocolo).

**Critério de concluído:**
- [ ] Handshake completo entre cliente e servidor com verificação OK nos dois testes positivos.
- [ ] Os dois testes negativos (assinatura e salt adulterados) resultam em desconexão com log de razão.

> [!warning] Armadilha nº 1 do TP inteiro
> A API `sign(data, padding, algorithm)` da `cryptography` aplica SHA-256 **internamente** sobre o que você passar. Então decida a convenção e aplique idêntica nos dois lados: ou (a) você passa o material cru `pk_S‖pk_C‖client_id‖salt` e deixa a biblioteca calcular o hash, ou (b) você passa o hash pré-calculado (aí haverá hash duplo, mas consistente se os dois lados fizerem igual). **Recomendo (a)** — é o que o enunciado descreve ("assina o hash SHA-256 do material"). O bug clássico é o remetente fazer (a) e o verificador fazer (b): a assinatura nunca confere e você passa horas caçando.
> Outra armadilha: concatenar os campos **sem separadores** é o especificado; qualquer mudança de ordem/encoding (hex em vez de raw, uuid textual em vez de 16B) quebra tudo. Raw bytes, sempre.

> [!example] Decisão a documentar (Anexo B)
> Por que autoassinado + pinning é aceitável aqui, mas não na web? Porque o TP é um sistema fechado com um único servidor conhecido: a "autoridade" é o próprio arquivo distribuído junto com o cliente. Na web, qualquer servidor pode ser novo para você — daí a necessidade de CAs (ICP-Brasil, navegadores), como visto na aula 11.

---
### Etapa 5 — Derivação das chaves E2E: ECDH entre pares + HKDF

> [!summary] Ficha rápida
> **Objetivo:** para cada par de clientes, derivar as duas chaves de direção (`Key_A2B`, `Key_B2A`) e preencher a tabela `peers` — o coração do E2E.
> **Tempo estimado:** ~5 h · **Depende de:** Etapa 4 · **Aulas que sustentam:** [[9_Troca de chaves privadas]] (DH), [[10_Key Derivation Function]] (KDF/salt), [[8_Função Hash e Mac]] (HMAC, base do HKDF)

**O que você está construindo e por quê.** Com as chaves públicas distribuídas (o servidor envia a pk do novo cliente a todos e as pks de todos ao novo — a função *rendezvous* do enunciado), cada cliente calcula o segredo compartilhado `Z_AB = ECDH(sk_A, pk_B)` usando a própria sk e a pk recebida. Pela propriedade do DH (as tintas da aula 9!), A e B chegam ao **mesmo** Z — e o servidor, que só tem chaves públicas, **não consegue** calculá-lo. É literalmente a garantia "servidor cego" do enunciado nascendo.

Z, porém, não é uma chave: é *material bruto*. Ele entra como **IKM** no HKDF (RFC 5869), que trabalha em dois estágios conceituais: `PRK = HKDF-Extract(salt=salt_srv, IKM=Z)` compacta o Z; depois `HKDF-Expand(PRK, info, L=16)` deriva quantas chaves você quiser, **rotuladas** — `info="A2B"` gera a chave do sentido A→B, `info="B2A"` a do sentido B→A. Dois porquês que você precisa saber defender na apresentação: (1) **chaves por direção** = separação de chaves; um nonce só precisa ser único *dentro da sua direção*, e uma chave comprometida num sentido não revela o outro; (2) o **salt do servidor** amarra a derivação a esta sessão específica (handshake novo → salt novo → chaves novas).

Conexão com a aula 10 (importante para não confundir na prova também): **HKDF ≠ Argon2**. Argon2 é *password KDF* — lento de propósito, para material fraco (senha humana). HKDF é *key derivation* — rápido, para material já de alta entropia (o Z de 32 bytes do ECDH). O `salt_srv` aqui é contexto de sessão, não defesa contra tabela precomputada.

Sobre a prática com a biblioteca: a classe `HKDF` da `cryptography` faz Extract+Expand **numa chamada só** (você passa `salt`, `info` e `length`, e chama `.derive(Z)`). Não existe "HKDF-Extract isolado" exposto — e não precisa: chamar a classe duas vezes, com o mesmo salt e infos `b"A2B"` e `b"B2A"`, produz exatamente o par de chaves do enunciado. Trate os estágios como conceito (bom para a prova e para a apresentação) e a chamada única como implementação.

**O que estudar antes:**
- Releia [[10_Key Derivation Function]] (foco: qual o papel do salt; por que KDF de senha é lento e esta não precisa ser) e [[8_Função Hash e Mac]] (HMAC — o HKDF é HMAC-SHA256 dentro).
- RFC 5869 (HKDF) — é curtinho; a seção 2 (Extract e Expand) liga exatamente com as fórmulas do enunciado.
- Docs da `cryptography`: seção **Key derivation → HKDF**.

**Tarefas:**
- [ ] Distribuição de pks: quando um novo cliente registra, o servidor (a) envia a pk dele para todos os conectados e (b) envia as pks existentes para ele. Sem isso, o E2E não começa.
- [ ] Ao receber a pk de um peer: construir `X25519PublicKey.from_public_bytes(pk)` e calcular `Z = sk_client.exchange(pk_obj)` (32 bytes).
- [ ] Derivar as chaves com `HKDF(algorithm=SHA256(), length=16, salt=salt_srv, info=<label>)` — chame duas vezes com `info=b"A2B"` e `info=b"B2A"` (labels **ASCII em bytes**, como no enunciado).
- [ ] **Regra de quem é "A"** (decisão de projeto → Anexo B): defina um critério determinístico para o par — recomendação: ordenar os dois `client_id` como bytes e o **menor é "A"**. Assim, para qualquer par, os dois lados concordam sobre quem deriva o quê: A usa `key_send = Key_A2B` e `key_recv = Key_B2A`; B, o inverso. Sem essa regra, cada lado chama a mesma chave de um nome diferente e o sistema "quase" funciona (o pior tipo de bug).
- [ ] Preencher a tabela `peers` do enunciado, por peer: `public_key`, `key_send`, `key_recv`, `seq_send: 0`, `seq_recv: -1`, `IV_base_send = secrets.token_bytes(4)`, `IV_base_recv: None` (aprende com o primeiro frame — ver Etapa 6).
- [ ] **Descartar Z** após derivar as chaves (o enunciado diz "opcional armazenar" — recomendo descartar: menos segredo em memória = menos coisa a vazar em dump/log).
- [ ] Teste de consistência (temporário, REMOVA depois): comparar o fingerprint de `key_send` (lado A) com o de `key_recv` (lado B) — devem ser **idênticos**; e `key_send`(B) == `key_recv`(A). Logue só os fingerprints, conforme a política.

**Critério de concluído:**
- [ ] O teste de consistência mostra as chaves casando nos dois lados (e ele é apagado em seguida).
- [ ] Tabelas `peers` completas nos dois clientes; Z não existe mais em memória.
- [ ] Você consegue explicar por que o servidor não tem como calcular Z (dica: ele nunca gerou par X25519 — só assina com RSA).

> [!warning] Armadilhas
> 1. O `salt_srv` do handshake é o **mesmo** para todas as derivações daquela conexão — o que diferencia cada par é o Z (que depende das pks). Não invente salt por par.
> 2. Labels são bytes (`b"A2B"`), não string — em Python `str` e `bytes` são diferentes e a API exige bytes.
> 3. `length=16` (chave AES-128), não 32 — o enunciado pede AES-**128**-GCM.

---

### Etapa 6 — Cifragem E2E: AES-128-GCM (nonce, AAD, seq_no)

> [!summary] Ficha rápida
> **Objetivo:** enviar e receber frames E2E cifrados e autenticados, com a estrutura exata do enunciado.
> **Tempo estimado:** ~5 h · **Depende de:** Etapa 5 · **Aulas que sustentam:** [[12_Protocolos de Segurança]] (AEAD!), [[8_Função Hash e Mac]] (MAC/tag), [[7_Criptografia]] (cifra de bloco × fluxo)

**O que você está construindo e por quê.** Abra a [[12_Protocolos de Segurança]]: um **AEAD** entrega confidencialidade + integridade + autenticidade numa única função, e ainda autentica **dados associados** (AAD) — dados que não são cifrados mas são protegidos contra adulteração. O AES-128-GCM que o TP pede é exatamente o AEAD da sua anotação ("muito usado em TLS 1.2 e 1.3"). A ligação com a aula 12 é direta: das três composições clássicas (MtE, E&M, EtM), a segura é **EtM** — e o GCM faz EtM internamente, com a tag verificada **antes** de qualquer decifragem; sem padding no modo (GCM opera tipo cifra de fluxo, modo CTR), o *padding oracle* da aula nem tem superfície de ataque. A tag de 16 bytes é a resposta do TP ao *forgery*: qualquer bit alterado → `InvalidTag`.

A estrutura do frame é a do enunciado: `[nonce 12B ‖ sender_id 16B ‖ recipient_id 16B ‖ seq_no 8B ‖ ciphertext+tag]`, com **AAD = sender_id ‖ recipient_id ‖ seq_no**. Pense no que o AAD compra: o relay poderia tentar **redirecionar** um frame (trocar o recipient_id para outra pessoa) ou **reordenar** (mexer no seq_no) — como esses campos fazem parte do AAD, qualquer dessas mexidas quebra a tag no destino. O nonce, por sua vez, é `IV_base (4B) ‖ seq_no (8B, big-endian)`: cada direção tem um IV_base sorteado por sessão e um contador que só cresce — com chave e contador por direção, a regra sagrada "nunca repetir (chave, nonce)" é satisfeita por construção.

**O que estudar antes:**
- Releia [[12_Protocolos de Segurança]] inteira (É a etapa) e o trecho de cifra de bloco × fluxo em [[7_Criptografia]].
- Docs da `cryptography`: `cryptography.hazmat.primitives.ciphers.aead` → **AESGCM** (`.encrypt(nonce, data, aad)` retorna `ct ‖ tag` juntos; `.decrypt(...)` levanta `InvalidTag`).
- Opcional, para brilhar na apresentação: NIST SP 800-38D §5.2 (requisitos de unicidade do nonce) e RFC 5116 (interface AEAD).

**Tarefas:**
- [ ] Construção do nonce por mensagem: `IV_base_send (4B) ‖ seq_no (8B big-endian)` — referência: `int.to_bytes(8, "big")`; o nonce completo (12B) vai **dentro do frame** (não é segredo; a unicidade é que importa).
- [ ] Cifrar: `AESGCM(key_send).encrypt(nonce, plaintext, aad)` com `aad = sender_id ‖ recipient_id ‖ seq_no` (os mesmos 40 bytes que vão no frame, cru, nesta ordem).
- [ ] Montar o frame na ordem do enunciado e respeitar o **limite de 4096 bytes de plaintext** — recusar no remetente (validação local) e validar no recebedor (junte com o limite de frame da Etapa 1: um length prefix maior que o máximo é erro de protocolo → desconexão).
- [ ] Decifrar: reconstruir o AAD a partir dos campos **recebidos no frame** e chamar `.decrypt(...)`; capturar `InvalidTag`.
- [ ] Políticas do contador (decisões → Anexo B): incrementar `seq_send` **após** cifrar com o valor atual (o primeiro frame usa seq 0, coerente com `seq_recv = -1` do recebedor) e registrar no README; nunca zerar `seq_send` durante a sessão (se precisar reiniciar, sessão nova = chaves novas + IV_base novo).
- [ ] No lado receptor, guardar `IV_base_recv` a partir do primeiro frame válido (o prefixo do nonce recebido) e, a partir daí, conferir que frames seguintes daquela direção usam o mesmo prefixo — barato e pega bagunça de sessão cedo.

**Critério de concluído:**
- [ ] A envia "olá" para B e B decifra corretamente (e vice-versa, exercitando a outra direção/chave).
- [ ] Teste negativo manual: alterar 1 byte do ciphertext → `InvalidTag`; alterar 1 byte do `recipient_id` (ou do `seq_no`) no frame → `InvalidTag` — e o servidor ainda encaminhou tudo, sem perceber nada (é a prova do "cego").

> [!warning] Armadilhas
> 1. O AAD no decrypt tem que ser **byte a byte idêntico** ao do encrypt (mesmos valores crus, mesma ordem). Um `str` em vez de `bytes` no id já basta para quebrar.
> 2. Direção certa da chave: quem envia usa `key_send`; quem recebe usa `key_recv` — e `key_send`(A) == `key_recv`(B) graças à regra da Etapa 5. Se a tag nunca confere mas o código "parece certo", suspeite primeiro das direções.
> 3. A biblioteca já concatena a tag ao ciphertext (retorno de `encrypt` tem 16 bytes a mais que o plaintext). Não adicione tag na mão duas vezes.

---
### Etapa 7 — Anti-replay e tratamento de erros (fail-closed)

> [!summary] Ficha rápida
> **Objetivo:** rejeitar frames repetidos/adulterados/inválidos de forma segura e com logs corretos — 20% da nota mora aqui.
> **Tempo estimado:** ~3 h · **Depende de:** Etapa 6 · **Aulas que sustentam:** [[12_Protocolos de Segurança]] (forgery), [[8_Função Hash e Mac]] (por que a tag sozinha não impede replay)

**O que você está construindo e por quê.** Insight contraintuitivo que você precisa consolidar: **a tag GCM não protege contra replay**. Um atacante que copia um frame *inteiro, intacto*, e o reenvia, tem tag válida — do ponto de vista do GCM, aquilo é uma mensagem perfeita. Replay é um ataque contra o **estado do protocolo**, não contra a criptografia; por isso o TP exige o `seq_no` monotônico por direção, mantido na tabela `peers`. A regra simples e suficiente para este trabalho: aceitar apenas `seq_no > seq_recv` (sem janela deslizante; o TLS 1.3 usa janela, e citar essa diferença na apresentação rende ponto). O `seq_recv` só é atualizado **depois** da decifragem bem-sucedida — a ordem importa: valida seq → decifra → atualiza contador.

O segundo pilar é a filosofia **fail-closed**: qualquer violação de protocolo (tag inválida, seq repetido, framing impossível, handshake inválido) encerra a conexão afetada e registra a razão. A política de logs do TP permite logar exatamente o que interessa nessas horas: razão da rejeição (`tag mismatch`, `replay rejected`, `bad framing`), ids e tamanhos — **nunca** o conteúdo, nonce, salt ou segredo.

**O que estudar antes:**
- Releia [[12_Protocolos de Segurança]] (seção de forgery — replay é a prima do forgery: o atacante mexe no protocolo, não na cripto).
- Seção "Testes mínimos obrigatórios" e "Política de logs" do PDF do TP (é literalmente o roteiro desta etapa).

**Tarefas:**
- [ ] Validação de sequência no recebedor: `seq_no` recebido ≤ `seq_recv` → rejeitar com log `replay rejected` (logando ids e o seq recebido — seq não é segredo).
- [ ] Ordem de validação fixada: (1) framing válido, (2) seq novo, (3) decifra/confere tag, (4) atualiza `seq_recv`, (5) entrega ao usuário.
- [ ] Política para `InvalidTag` (decisão → Anexo B): recomendo **desconectar** — tag inválida significa ataque ativo ou bug grave; no mínimo, descartar o frame e logar. Documente o que escolher, porque a rubrica pede "proteções demonstradas".
- [ ] Erros de framing (length prefix absurdo, `IncompleteReadError`, bytes sobrando) → desconexão segura, sem crash (a rubrica testa isso explicitamente).
- [ ] Blindar o servidor: exceção em UMA conexão não pode derrubar as outras (cada conexão tem sua task; captura e loga no escopo dela).
- [ ] Vetor de teste do recebedor: guardar cópia do último frame E2E válido enviado (para o teste de replay da Etapa 9) e um modo "atacante" no cliente de testes que aplica XOR de 1 byte num byte aleatório do frame (para o teste de bitflip).

**Critério de concluído:**
- [ ] Reenviar um frame válido → rejeitado por replay (log correto).
- [ ] Enviar frame com 1 bit alterado → rejeitado por tag (log correto).
- [ ] Enviar lixo/framing mentiroso → desconexão limpa do lado servidor, outros clientes continuam funcionando.
- [ ] Nenhum log contém plaintext, nonce, salt, chave ou Z.

---

### Etapa 8 — Servidor relay + mensagens administrativas + ciclo de vida

> [!summary] Ficha rápida
> **Objetivo:** roteamento cego de frames E2E, mensagens administrativas ordenadas, e ciclo de vida completo (entrada, saída, reconexão) sem vazamento de estado.
> **Tempo estimado:** ~4 h · **Depende de:** Etapa 7 · **Aulas que sustentam:** [[7_Criptografia]] (E2E: "encriptada no emissor, decifrada só no destinatário")

**O que você está construindo e por quê.** O servidor agora vira o que o enunciado chama de relay/rendezvous: lê o frame E2E, olha o `recipient_id`, localiza o `writer` na tabela `sessions` e **reenvia os bytes exatamente como chegaram** — sem tocar no ciphertext, porque não poderia decifrar nem re-cifrar (não tem as chaves E2E; e não deve ter, é o desenho do sistema). Isso é a materialização da frase da aula 7 sobre criptografia fim a fim: cifrada no emissor, decifrada só no destinatário. Consequentemente, o servidor precisa de uma segunda conversa paralela com cada cliente: as **mensagens administrativas** (confirmação de registro, lista de peers, entrada/saída de clientes, erros), que o enunciado protege com o contador próprio `seq_send` do servidor — ordenação e anti-replay para o plano de controle.

O ciclo de vida fecha o sistema: cliente desconectou → remover entrada de `sessions` e avisar os outros; cliente reconectou com o mesmo `client_id` → handshake completo de novo, `salt` novo, contadores zerados, chaves E2E novas (o enunciado proíbe reutilizar salt/seq antigos — é forward secrecy na prática: sessão passada não "contamina" nem é contaminada pela nova).

**O que estudar antes:**
- Docs do Python: `asyncio.Lock` (a tabela `sessions` é mutada por várias tasks — entrada, saída, roteamento — e precisa de exclusão mútua).
- PDF do TP: seção "Estrutura de Dados no Servidor" e a observação sobre a troca de pks a cada novo cliente (já implementada na Etapa 5 — aqui só falta o aviso de saída).

**Tarefas:**
- [ ] Roteamento E2E no servidor: `recipient_id` → lookup em `sessions` → `writer.write(frame)` verbatim; destinatário inexistente/desconectado → mensagem administrativa de erro ao remetente (nada de crash).
- [ ] Distinguir frame E2E de frame administrativo (decisão → Anexo B, com recomendação: reservar um valor especial de `sender_id`/`recipient_id` — por exemplo, 16 bytes zerados significando "servidor" — em vez de adicionar um byte extra de tipo ao frame do enunciado).
- [ ] Mensagens administrativas com payload textual (ex.: JSON) carregando `seq` do servidor crescente + tipo + dados (lista de peers, motivo de erro). Decisão → Anexo B: o TP não exige confidencialidade para esse plano (só ordenação e anti-replay) — recomendo transmiti-las sem cifragem, mas **jamais** colocar nelas qualquer segredo (elas são metadados: ids, tamanhos, avisos).
- [ ] Saída: conexão caiu → remover de `sessions` (sob lock), notificar os pares com mensagem administrativa de saída, encerrar task da conexão.
- [ ] Reconexão com mesmo `client_id`: fluxo de handshake completo reexecutado; conferir que salt e contadores são novos e que as chaves E2E antigas não são reutilizadas em nenhum lado.
- [ ] `asyncio.Lock` em toda leitura-modificação-escrita de `sessions` (registro, remoção, roteamento).
- [ ] Teste do "servidor curioso" para a demo: adicionar um log temporário no relay mostrando que ele só vê bytes opacos (tamanho + ids) — remova depois, mas use na apresentação.

**Critério de concluído:**
- [ ] Com 3 clientes conectados: A envia para B e **só** B decifra (C fica surdo ao frame).
- [ ] C conecta → A e B recebem a pk dele; C desconecta → A e B são notificados e o sistema segue de pé.
- [ ] Reconexão de um `client_id` existente funciona e invalida o estado antigo (frames da sessão velha não passam na nova).
- [ ] O servidor não detém nenhuma chave simétrica em memória (revise a estrutura `sessions` — só writer, pk, contadores e salt).

---
### Etapa 9 — Testes obrigatórios da rubrica

> [!summary] Ficha rápida
> **Objetivo:** transformar os 4 testes mínimos do enunciado em um roteiro reproduzível — e demonstrável.
> **Tempo estimado:** ~4 h · **Depende de:** Etapa 8 · **Aulas que sustentam:** [[12_Protocolos de Segurança]] (aqui você *interpreta o atacante*)

**O que você está construindo e por quê.** As aulas mostraram ataques (padding oracle, forgery) do ponto de vista do defensor; agora você vai se colocar do outro lado, como a criptoanálise faz: criar um **cliente atacante** — um script que participa do protocolo como qualquer cliente, mas mentindo deliberadamente. Cada teste da rubrica corresponde a uma garantia do sistema, e a demonstração de cada rejeição é o que rende os 20% de "proteções contra replay e tampering demonstradas". Monte a matriz abaixo como tabela no seu README e execute-a ao vivo na apresentação.

**Tarefas:**
- [ ] Construir o cliente atacante com 4 modos, um por teste:
  - [ ] **T1 — E2E feliz:** dois clientes honestos trocam mensagens; o destinatário exibe o texto correto.
  - [ ] **T2 — Bitflip:** capturar um frame E2E válido, inverter 1 byte (do ciphertext OU do AAD, teste os dois) e reenviar → `InvalidTag` no destino.
  - [ ] **T3 — Replay:** reenviar um frame válido já entregue (mesmos bytes, inclusive seq) → rejeitado pela checagem de `seq_no`.
  - [ ] **T4 — Framing inválido:** enviar um length prefix mentiroso (maior que o permitido, ou maior que o payload real) → desconexão segura do servidor.
- [ ] Registrar a observação esperada de cada teste (log que aparece, comportamento de conexão) na matriz de aceitação do README:

| Teste | Entrada do atacante | Resultado esperado | Garantia demonstrada |
|---|---|---|---|
| T1 | — | Mensagem chega correta | Confidencialidade + integridade |
| T2 | 1 byte alterado | `InvalidTag`, frame rejeitado | Integridade / anti-forgery |
| T3 | Frame válido reenviado | `replay rejected` | Anti-replay (seq_no) |
| T4 | Length prefix inválido | Desconexão segura | Robustez do framing |

- [ ] Opcional: automatizar como testes (módulo `pytest` com fixtures que sobem servidor + 2 clientes em localhost) — ganha carinho na rubrica de organização.
- [ ] Preparar a demo: roteiro de execução em terminais separados (1 servidor + 2 clientes + 1 atacante), com os logs de rejeição visíveis.

**Critério de concluído:**
- [ ] Os 4 testes passam na sua máquina, na sequência, sem intervenção manual além do esperado.
- [ ] Você sabe apontar, para cada rejeição, a linha/etapa do seu código responsável (o professor pode perguntar exatamente isso).

---

### Etapa 10 — Higiene de segurança, logs e documentação

> [!summary] Ficha rápida
> **Objetivo:** auditoria da política de logs, README completo e apresentação montada — os 25% finais da rubrica.
> **Tempo estimado:** ~4 h · **Depende de:** Etapa 9

**O que você está construindo e por quê.** A rubrica dá 10% por "práticas de segurança (logs, não expor chaves)" — é a nota mais barata do trabalho e a mais fácil de perder por descuido. Faça uma **auditoria de segredos** no código como se fosse um atacante: onde segredos existem (sk X25519, sk RSA, Z, chaves derivadas, salt, nonces, plaintext), quem os imprime, o que acontece quando uma exceção explode perto deles (mensagens de exceção podem carregar dados!). Depois, o README fecha o ciclo: um colega deve conseguir rodar o sistema lendo só ele, e você deve conseguir apresentar cada trecho sem depender de improviso.

**Tarefas:**
- [ ] **Auditoria de logs** (política do TP): verificar que NUNCA são logados: chaves privadas, Z, salt cru, nonces, plaintext. Permitidos e já implementados: eventos de conexão/desconexão, `client_id`, tamanhos, razões de rejeição, fingerprints.
- [ ] Auditar exceções: blocos de erro perto de operações criptográficas logam a **razão** (`InvalidTag`, `InvalidSignature`), nunca os dados de contexto.
- [ ] Conferir `server.key` no `.gitignore` e fora do pacote distribuído; certificado pinado é público e pode ir.
- [ ] README final: pré-requisitos, como gerar o certificado (uma vez), como rodar servidor e N clientes, descrição resumida do protocolo (reaproveite o diagrama mermaid da seção 1), tabela de testes da Etapa 9, e o resumo do **Anexo B** (decisões e justificativas).
- [ ] Preparar a apresentação usando o checklist do professor (explicação do protocolo, demo, validação de segurança, estrutura de dados, explicação do código por integrante): divida os trechos — handshake, derivação de chaves, cifragem/anti-replay, roteamento/relay — entre os integrantes.
- [ ] Ensaio do roteiro da demo uma vez inteira antes do dia (o T4 derruba conexões: saiba reiniciar tudo em 30 segundos).

**Critério de concluído:**
- [ ] `grep` por impressões/log no código não encontra nenhum segredo (faça a busca por nomes das variáveis de segredo).
- [ ] Um colega (ou você, do papel) consegue rodar o sistema inteiro seguindo só o README.
- [ ] Cada integrante sabe explicar o trecho que lhe coube E como ele se conecta às garantias gerais.

---

## Anexo A — Estrutura sugerida de arquivos (Python)

O enunciado não impõe layout, mas a rubrica premia organização. Sugestão com separação por **responsabilidade** (e o bônus: código criptográfico isolado em módulos próprios é auditável — o professor encontra cada garantia num arquivo):

```
WhatsUp/
├── server.py               # servidor: asyncio, accept loop, relay, admin
├── client.py               # cliente: boot, handshake, loop de envio/recepção, CLI de chat
├── protocol/
│   ├── framing.py          # send_frame/recv_frame (prefixo 4B big-endian, limites)
│   ├── ids.py              # UUID v4 ↔ 16 bytes, helpers de exibição para logs
│   ├── handshake.py        # registro, salt, montagem/verificação da assinatura RSA-PSS
│   ├── keys.py             # X25519 (geração/troca), HKDF (derivação A2B/B2A), fingerprints
│   ├── crypto.py           # AES-128-GCM: nonce (IV_base‖seq), AAD, encrypt/decrypt do frame
│   └── admin.py            # mensagens administrativas do servidor (tipos, seq_send)
├── tools/
│   └── gen_cert.py         # one-off: par RSA + server.crt autoassinado
├── certs/
│   ├── server.crt          # público — vai para os clientes (pinning)
│   └── server.key          # PRIVADO — .gitignore, nunca distribuir
├── tests/
│   ├── attacker_client.py  # modos T2 bitflip / T3 replay / T4 framing
│   └── test_e2e.py         # (opcional) automação com pytest
├── .gitignore              # server.key, venv, __pycache__
└── README.md               # rodar + protocolo + decisões (Anexo B) + matriz de testes
```