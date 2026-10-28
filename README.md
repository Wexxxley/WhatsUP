# WhatsUp — Sistema de Mensageria Multi-Cliente (E2E)

## Visão geral

O WhatsUp é uma aplicação de mensageria com criptografia ponta a ponta
(E2E). Clientes trocam mensagens cifradas, enquanto o
servidor atua como relay: ele gerencia conexões e encaminha frames, mas não
decifra o conteúdo das mensagens E2E.

Cada cliente cria um identificador UUID e um par de chaves X25519 toda vez que o cliente é reiniciado. O cliente autentica o servidor durante o handshake, registra sua chave pública
e recebe os anúncios feito pelo servidor dos peers online.

### Garantias e mecanismos

1. **Confidencialidade:** AES-128-GCM cifra o conteúdo das mensagens.
2. **Integridade:** a tag de autenticação do AESGCM detecta adulterações;
3. **Autenticidade do servidor:** Certificado (com RSA-PSS) autoassinado pinado pelo cliente autenticam a resposta inicial do servidor.
4. **Sigilo futuro:** pares efêmeros X25519 são usados para
   derivar chaves E2E por sessão.
5. **Proteção contra replay:** contadores de sequência por direção rejeitam
   mensagens repetidas ou fora de ordem.

> **Escopo da autenticação:** o handshake autentica a resposta inicial do
> servidor. Os anúncios de entrada/saída de peers posteriores são frames de
> controle recebidos pela conexão TCP e não possuem assinatura ou MAC próprio
> nesta implementação.

## Navegação

- [Estrutura do projeto](#estrutura-do-projeto)
- [Pré-requisitos e execução](#pre-requisitos-e-execucao)
- [Conceitos usados no protocolo](#conceitos-usados-no-protocolo)
- [Fluxo do protocolo](#fluxo-do-protocolo)
- [Exemplo dos contadores por cliente](#exemplo-dos-contadores-por-cliente)
- [Assinatura digital não é criptografia](#assinatura-digital-nao-e-criptografia)
- [Dicionário de termos](#dicionario-de-termos-e-mapeamento-com-os-estudos)
- [Observações sobre X25519 e ECDH](#observacoes-sobre-x25519-e-ecdh)

## Estrutura do projeto

```text
WhatsUp/
|-- server.py                  # Servidor TCP: relay e gerenciamento de sessões
|-- client.py                  # Cliente e interface interativa no terminal
|-- protocol/
|   |-- framing.py             # Prefixo de tamanho e leitura/escrita de frames
|   |-- ids.py                 # Geração e formatação de UUID v4
|   |-- handshake.py           # Assinatura e verificação do handshake
|   |-- keys.py                # Pares X25519 e serialização de chaves
|   |-- spec.py                # Tamanhos e constantes do protocolo
|   `-- crypto.py              # HKDF, AES-GCM e validação anti-replay
|-- tools/
|   `-- generate_certificate.py # Geração do certificado e da chave do servidor
|-- certs/
|   |-- server.crt             # Certificado público pinado pelos clientes
|   `-- server.key             # Chave privada RSA do servidor
`-- tests/                     # Testes unitários, de protocolo e integração
```

## Pré-requisitos e execução

### Dependências

Use Python 3.10 ou superior e instale `cryptography`:

```bash
python3 -m pip install cryptography
```

### Certificado do servidor

Ao iniciar, o servidor verifica se `certs/server.key` e `certs/server.crt`
existem. Se faltar qualquer um, gera um novo par RSA e certificado autoassinado.
Também é possível gerá-los manualmente:

```bash
python3 tools/generate_certificate.py
```

O certificado `certs/server.crt` precisa estar disponível no cliente para a
verificação por pinning. A chave privada `certs/server.key` deve permanecer
protegida e nunca deve ser distribuída aos clientes.
Se apenas um dos arquivos estiver presente, o servidor gera um novo par
completo; como o certificado muda, os clientes precisam atualizar o pin.

### Iniciar o servidor e os clientes

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

### Criptografia simétrica e assimétrica

- **Simétrica:** a mesma chave compartilhada cifra e decifra os dados. É
  eficiente para mensagens; neste projeto, usa-se AES-128-GCM.
- **Assimétrica:** utiliza um par de chave privada e chave pública. X25519
  estabelece segredos compartilhados; RSA-PSS assina a resposta do servidor.

### Hash, MAC e AEAD

- **Hash:** função determinística e unidirecional que resume dados em um valor
  de tamanho fixo. Hashes também podem produzir *fingerprints* de chaves para
  depuração.
- **MAC (Message Authentication Code):** código de autenticação com chave que
  verifica integridade e autenticidade.
- **AEAD (Authenticated Encryption with Associated Data):** cifra o conteúdo,
  autentica-o e também autentica dados associados que permanecem visíveis, como
  os IDs e o número de sequência do frame. AES-GCM é um algoritmo AEAD


### Diffie-Hellman, MITM e HKDF

Diffie-Hellman permite que duas partes obtenham um segredo compartilhado sem
transmiti-lo pela rede. DH puro não autentica o outro lado e, portanto, pode
ser vulnerável a um ataque *Man-in-the-Middle* (MITM). O handshake RSA-PSS
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

Um certificado X.509 associa uma identidade a uma chave pública. Neste projeto,
o certificado do servidor é autoassinado e pinado localmente pelo cliente
(uma confiança configurada fora da cadeia de uma CA pública).

### Entropia

Gerar entropia significa obter aleatoriedade imprevisível. Chaves
criptográficas, salts e bases de IV precisam de fontes aleatórias seguras. Se
um gerador pseudoaleatório usar uma seed fraca ou previsível, valores
criptográficos produzidos por ele podem ser adivinhados.

## Fluxo do protocolo

O fluxo abaixo acompanha as fases do diagrama e a ordem executada pelo código.
Quando a especificação do PDF e a implementação diferem, a diferença é indicada.

### Preparação do servidor

Ao iniciar, o servidor verifica se `certs/server.key` e `certs/server.crt`
existem. Se um dos arquivos estiver ausente, gera um novo par e carrega as
credenciais antes de abrir o listener; não gera um novo par RSA para cada
cliente. O certificado público correspondente precisa estar pinado no cliente.
Se o par foi regenerado porque um dos arquivos faltava, atualize também o
certificado pinado pelos clientes.

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
material com RSA-PSS e SHA-256, usando `server.key`, e responde:

```text
prefixo de tamanho (4B) ||
[tamanho do certificado] || [server.crt] ||
[tamanho da assinatura] || [assinatura RSA-PSS] || [salt_srv]
```

O cliente compara o certificado recebido com o certificado pinado, reconstrói
o material com seu próprio `pk_C` e `client_id` e verifica a assinatura com
`pk_S`. Se o pin ou a assinatura não corresponder, o handshake é interrompido
(*fail-closed*). O material assinado trafega em claro: a assinatura comprova
integridade/origem, mas não cifra os dados.

O `salt_srv` autentica e identifica essa resposta do handshake. Na derivação
E2E descrita abaixo, a implementação atual não o usa como salt comum entre os
dois peers.

### Fase 3 — Registro da sessão e anúncios de peers

Depois de responder ao handshake, o servidor entra em `sessions_lock`, envia
ao cliente novo a quantidade de peers online e, em seguida, um frame de 48
bytes (`client_id || pk_client`) para cada peer existente. Também envia o
registro do cliente novo aos clientes que já estavam conectados. Só depois
desses envios o servidor insere a nova sessão em `sessions`, com `seq_send=0`,
`seq_recv=-1` e o `salt_srv` do handshake.

O cliente novo lê cada anúncio inicial e deriva chaves para cada peer. Os
clientes já conectados recebem o anúncio do novo cliente no loop de recepção e
fazem a mesma derivação. Os anúncios de saída usam o ID do cliente seguido por
32 bytes zero (`PEER_LEAVE_PUBLIC_KEY`).

Esses anúncios são frames de controle, não mensagens E2E, e não possuem
assinatura nem MAC individual nesta implementação. Portanto, o handshake
autentica a resposta inicial do servidor, mas não autentica criptograficamente
cada chave pública de peer anunciada depois. Um servidor que substitua esses
anúncios poderia tentar intermediar a derivação E2E.

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

O código calcula um salt determinístico comum ao par, ordenando os IDs
binários:

```text
pair_salt = SHA256(
    b"WhatsUp E2E" || min(client_id_A, client_id_B) ||
    max(client_id_A, client_id_B)
)
```

Com `Z_AB` e `pair_salt`, HKDF-SHA256 deriva duas chaves de 16 bytes, usando os
rótulos `b"A"` e `b"B"`. O menor ID do par é A; a chave A é usada no sentido
A→B e a chave B no sentido B→A. Cada cliente escolhe sua chave de envio e
recepção conforme sua posição no par. Isso difere do PDF, que descreve o uso
de `salt_srv` e os rótulos `A2B` e `B2A`.

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
`pk_S || pk_C || client_id || salt_srv` com `server.key`, ele não cifra esses
dados. A assinatura permite verificar a integridade e a origem do material; o
conteúdo assinado e o certificado trafegam em claro junto dela.

A resposta do handshake contém:

```text
[tamanho do certificado] ||
[server.crt (certificado contendo pk_S)] ||
[tamanho da assinatura] ||
[assinatura RSA-PSS] ||
[salt_srv]
```

O cliente valida o certificado por pinning e verifica a assinatura RSA-PSS com
a chave pública do certificado. Isso autentica a resposta inicial do servidor;
não autentica individualmente os anúncios de peers enviados depois.

## Dicionário de termos e mapeamento com os estudos

| Termo / nomenclatura | Significado no projeto | Material relacionado em `Estudos/` |
|---|---|---|
| `client_id` | Identificador UUID v4 de 16 bytes do cliente. | Identidade e sessões |
| `sk` / `pk` | Chave privada (`sk`) e chave pública (`pk`). | [[7_Criptografia]] e [[9_Troca de chaves privadas]] |
| `X25519` | Curva usada para o Diffie-Hellman efêmero. | [[9_Troca de chaves privadas]] |
| `Z_AB` | Segredo bruto compartilhado calculado via ECDH entre A e B. | [[9_Troca de chaves privadas]] |
| `salt_srv` | Salt aleatório gerado pelo servidor durante o handshake. | [[10_Key Derivation Function]] |
| `HKDF` | Função baseada em HMAC para derivar chaves de `Z_AB`. | [[10_Key Derivation Function]] |
| `server.crt` / pinning | Certificado autoassinado do servidor pinado no cliente. | [[11_Assinatura e certificado digital]] |
| `RSA-PSS` | Algoritmo de assinatura usado no handshake do servidor. | [[11_Assinatura e certificado digital]] |
| `AES-128-GCM` | Cifra AEAD que fornece confidencialidade e autenticação. | [[12_Protocolos de Segurança]] |
| `AAD` | Dados autenticados, mas não cifrados: remetente, destinatário e sequência. | [[12_Protocolos de Segurança]] |
| `seq_no` | Contador por direção usado para nonce, ordenação e anti-replay. | [[12_Protocolos de Segurança]] |


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

## Diagrama de sequência

O diagrama a seguir resume o registro dos clientes, o handshake com o servidor,
a derivação das chaves E2E e o envio e recebimento de uma mensagem:

![Diagrama de sequência do protocolo WhatsUp](./DiagramaDeSequencia-WhatsUP.svg)
