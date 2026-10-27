# WhatsUp — Sistema de Mensageria Segura Multi-Cliente (E2E)


---


## Visão Geral

Aplicação de mensageria com criptografia ponta-a-ponta (**E2E**). O servidor atua como um **relay**, sem capacidade de decifrar o conteúdo das mensagens trocadas entre os clientes. Cada cliente realiza um handshake autenticado com o servidor para registrar sua chave pública efêmera/temporária e eceber as chaves públicas dos demais participantes.

### Garantias de Segurança
1. **Confidencialidade:** As mensagens são cifradas de ponta a ponta utilizando **AES-128-GCM (AEAD - Authenticated Encryption with Associated Data)** que é do tipo **Encrypt-then-MAC (EtM)**.
2. **Integridade:** Qualquer adulteração no tráfego é detectada pela tag de autenticação GCM (`InvalidTag`).
3. **Autenticidade:** O servidor é autenticado perante os clientes utilizando **RSA-PSS com SHA-256** e certificado autoassinado pinado.
4. **Sigilo Perfeito:** Obtido através do uso de chaves efêmeras/temporárias **X25519 (ECDHE -  Diffie-Hellman baseado em Curvas Elípticas)** a cada sessão.
5. **Anti-Replay:** Proteção contra reenvio de mensagens.

- **Handshake** etapa de autenticação entre o cliente o servidor após a abertura da conexão TCP e o envio do registro inicial (client_id + pk_C).

---

## Estrutura do Projeto

```
WhatsUp/
├── server.py               # Servidor TCP assíncrono (relay cego e gerenciamento de sessões)
├── client.py               # Cliente de mensageria
├── protocol/
│   ├── framing.py          # Delimitação de frames com prefixo de 4 bytes (big-endian)
│   ├── ids.py              # Manipulação de UUID v4
│   ├── handshake.py        # Handshake
│   ├── keys.py             # Pares X25519, serialização raw e fingerprints
│   ├── crypto.py           # Cifragem AES-128-GCM, HKDF-SHA256 e anti-replay
├── tools/
│   └── generate_certificate.py 
├── certs/
│   ├── server.crt          # Certificado público do servidor (pinado nos clientes)
│   └── server.key          # Chave privada do servidor
```

---

## Pré-requisitos e Execução

### 1. Dependências
Certifique-se de ter o Python 3.8+ e a biblioteca `cryptography` instalados:
```bash
pip install cryptography
```

### 2. Geração de Certificados (Caso necessário)
O servidor requer um par de chaves RSA e um certificado autoassinado:
```bash
python3 tools/generate_certificate.py
```

### 3. Executando o Servidor
```bash
python3 server.py
```

### 4. Executando os Clientes
Em outro terminal, execute o cliente:
```bash
python3 client.py
```

Após o handshake, o cliente abre uma interface interativa no terminal. Use as setas para selecionar um peer e Enter para abrir a conversa. Digite a mensagem e pressione Enter para enviar; as mensagens recebidas aparecem no histórico sem interromper a digitação. Pressione Esc ou digite `/voltar` para retornar à lista, e `q` na lista ou `/sair` na conversa para encerrar.

Entradas e saídas de peers são atualizadas automaticamente. As chaves E2E são derivadas com um salt comum e determinístico por par de IDs, pois o salt de handshake é específico de cada conexão.

### 5. Executando a Suíte de Testes
Para rodar todos os testes unitários e de integração
```bash
python3 -m unittest discover tests
```

---

# Fluxo da Aplicação


## 1. Visão Geral e Arquitetura

---

## 2. Dicionário de Conceitos e Termos

1. **Criptografia Simétrica vs. Assimétrica:**
   - **Simétrica:** Usa a mesma chave compartilhada para cifrar e decifrar. Extremamente rápida, (Ex: algorítmo `AES-128-GCM`).
   - **Assimétrica:** Usa um par de chaves: uma chave privada e uma chave pública distribuída livremente. Usada no estabelecimento seguro e na autenticação (`X25519` e `RSA`).

2. **Função Hash e MAC:**
   - **Hash:** Função determinística, unidirecional que comprime dados em tamanho fixo. Usada para integridade e para criar **fingerprints** de chaves nos logs.
   - **MAC (Message Authentication Code):** Um "checksum com chave" que garante integridade e autenticidade. O modo `AES-GCM` utilizado no projeto já embute autenticação forte (equivalente a um MAC moderno).

3. **Diffie-Hellman e o Problema do MITM:**
   - **Diffie-Hellman:** Permite que duas partes estabeleçam um segredo compartilhado sobre um canal inseguro sem nunca transmitir o segredo.
   - **O Problema:** O DH puro é vulnerável a ataques de *Man-in-the-Middle (MITM)* porque não autentica quem está do outro lado. O TP resolve isso combinando curvas elípticas com assinaturas digitais RSA-PSS.

4. **Derivação de Chaves — HKDF:**
   - **HKDF (HMAC-based Key Derivation Function):** Diferente do Argon2 (focado em senhas e CPU/Memory-hard), o HKDF é rápido e deriva chaves robustas utilizando um `salt` e rótulos (`info`).

5. **Assinaturas Digitais e Certificados X.509:**
   - **Assinatura:** O emissor assina o hash da mensagem com sua chave privada ($sk$), provando autoria e integridade.
   - **Certificado:** Vínculo oficial entre uma identidade e uma chave pública, assinado por uma Autoridade Certificadora (CA). No projeto, usamos um certificado autoassinado *pinado* no cliente ("CA caseira").

6. **Protocolos de Segurança e AEAD ([[12_Protocolos de Segurança]]):**
   - *AEAD (Authenticated Encryption with Associated Data):* Combina confidencialidade, integridade e autenticidade, além de proteger dados associados (cabeçalhos do protocolo) contra adulteração. O algoritmo escolhido é o **AES-128-GCM**, que opera na composição mais segura (*Encrypt-then-MAC* embutida)

---

## 3. Fluxo Passo a Passo da Aplicação

### Passo 1: Conexão de Rede e Framing (TCP)
- **O que acontece:** O cliente abre uma conexão TCP assíncrona com o servidor (`asyncio`).
- **O problema do TCP:** O TCP é um fluxo contínuo de bytes sem fronteiras de mensagens. Mensagens grandes podem ser fragmentadas ou mensagens pequenas podem chegar juntas ("grudadas").
- **Solução (Framing):** Todo pacote trafegado na rede é precedido por um **prefixo de 4 bytes em big-endian** (`struct >I`) que indica exatamente o tamanho do payload em bytes. O receptor lê exatamente esses bytes (`readexactly`), evitando truncamentos ou vazamento de dados entre frames.

---

### Passo 2: Identidade do Cliente (`client_id` UUID v4)
- **O que acontece:** No momento em que o cliente inicia, ele gera um identificador único de 16 bytes baseado em **UUID v4** (~122 bits aleatórios).
- **Finalidade:** Esse ID identifica univocamente o cliente perante o servidor e os demais peers, sem necessidade de um banco de dados centralizado de nomes.

---

### Passo 3: Registro e Par Efêmero X25519
- **O que acontece:** 
  1. O cliente gera um par de chaves efêmeras usando a curva elíptica **X25519** (`X25519PrivateKey.generate()`). A chave privada ($sk_C$) fica estritamente na memória; a chave pública ($pk_C$) é serializada em formato cru de 32 bytes (`Encoding.Raw`).
  2. O cliente envia ao servidor um frame de registro contendo: `client_id` (16B) + `pk_C` (32B).
  3. O servidor armazena a sessão na tabela interna: `sessions[client_id] = {writer, public_key, seq_send=0, seq_recv=-1, salt}`.
- **Conceito:** O uso de chaves efêmeras a cada conexão garante o **sigilo perfeito (*forward secrecy*)**: se a chave de uma sessão futura ou passada for comprometida, as sessões atuais permanecem seguras.

---

### Passo 4: Handshake Autenticado (RSA-PSS + Certificado Pinado)
Para evitar que um invasor interceptador (MITM) finja ser o servidor ou substitua a chave pública do cliente, o servidor realiza um handshake criptografado:

1. **Geração do Salt:** O servidor gera um `salt_srv` aleatório de 16 bytes (`secrets.token_bytes(16)`).
2. **Material Assinado:** O servidor monta uma string binária concatenada exatamente nesta ordem:
   $$\text{Material} = pk_S \parallel pk_C \parallel \text{client\_id} \parallel salt\_srv$$
   onde $pk_S$ é a chave pública do servidor extraída de seu certificado.
3. **Assinatura RSA-PSS:** O servidor assina o hash SHA-256 desse material usando sua chave privada RSA de longo prazo (`server.key`), aplicando o esquema **RSA-PSS** com SHA-256.
4. **Resposta do Handshake:** O servidor envia de volta ao cliente: `[tamanho cert || server.crt || tamanho assinatura || assinatura || salt_srv]`.
5. **Validação no Cliente:**
   - O cliente compara o certificado recebido (`server.crt`) com o certificado **pinado** armazenado localmente em seu disco. Se houver divergência, a conexão é encerrada imediatamente (*fail-closed*).
   - O cliente extrai $pk_S$, remonta o material exatamente na mesma ordem com seus próprios dados e verifica a assinatura usando `server_pub_key.verify(...)`.
   - Se a assinatura for válida, o cliente extrai o `salt_srv`.

---

### Passo 5: Distribuição de Chaves e Derivação de `Z_AB` (ECDH + HKDF)

Esta é a etapa central do modelo de **Criptografia Fim a Fim (E2E)** e onde surge o termo **`Z_AB`**:

#### O que é `Z_AB`?
- **`Z_AB`** é o **segredo bruto compartilhado** (*shared secret*) resultante de uma troca **Diffie-Hellman baseada em Curvas Elípticas (ECDH)** entre duas partes (Cliente A e Cliente B).
- Quando o Cliente A recebe a chave pública de B ($pk_B$), ele calcula:
  $$Z_{AB} = \text{ECDH}(sk_A, pk_B)$$
- Analogamente, o Cliente B calcula com sua chave privada ($sk_B$) e a chave pública de A ($pk_A$):
  $$Z_{AB} = \text{ECDH}(sk_B, pk_A)$$
- **A Mágica do Diffie-Hellman:** Devido à propriedade matemática das curvas elípticas, **ambos os lados chegam exatamente ao mesmo valor de $Z_{AB}$**, sem que nenhuma chave privada jamais trafegue pela rede. 
- **O Servidor é Cego:** Como o servidor nunca participa dessa operação (ele apenas repassa as chaves públicas), ele **não possui** as chaves privadas e, portanto, **é matematicamente incapaz de calcular $Z_{AB}$**.

#### Derivação de Chaves com HKDF (Baseado em [[10_Key Derivation Function]]):
Como o segredo bruto $Z_{AB}$ não deve ser usado diretamente como chave de cifragem, ele é alimentado em uma função **HKDF-SHA256**:
$$\text{PRK} = \text{HKDF-Extract}(salt=salt\_srv, IKM=Z_{AB})$$
$$\text{Key}_{A2B} = \text{HKDF-Expand}(\text{PRK}, info=b\text{"A2B"}, length=16)$$
$$\text{Key}_{B2A} = \text{HKDF-Expand}(\text{PRK}, info=b\text{"B2A"}, length=16)$$

- **Regra Determinística (Quem é A e quem é B?):** Para que ambos os lados saibam qual chave usar para enviar e qual usar para receber, o sistema ordena os dois `client_id` como bytes. O **menor ID é definido como "A"** e o maior como "B".
  - Se você for A: $\text{Key}_{send} = \text{Key}_{A2B}$ e $\text{Key}_{recv} = \text{Key}_{B2A}$.
  - Se você for B: o inverso.
- **Descarte do Segredo:** Após a derivação, $Z_{AB}$ é imediatamente descartado da memória para evitar vazamentos.

---

### Passo 6: Plano de Dados — Cifragem E2E com AES-128-GCM (AEAD)

Quando o Cliente A quer enviar uma mensagem para o Cliente B:

1. **Estrutura do Nonce:** Para cada mensagem, um nonce único de 12 bytes é gerado combinando um `IV_base` aleatório de 4 bytes e o contador de sequência (`seq_no`) de 8 bytes (em big-endian):
   $$\text{Nonce} = IV_{base} \parallel seq\_no$$
2. **AAD (Authenticated Associated Data):** Dados que não são cifrados, mas cuja integridade é garantida pela tag do AEAD:
   $$\text{AAD} = \text{sender\_id} \parallel \text{recipient\_id} \parallel seq\_no$$
3. **Cifragem (AES-128-GCM):** O texto claro é cifrado usando `Key_send` com o modo **AES-128-GCM** (que implementa internamente a composição segura *Encrypt-then-MAC*). O resultado produz o `ciphertext` acompanhado de uma tag de autenticação de 16 bytes.
4. **Montagem do Frame E2E:**
   $$\text{Frame} = [\text{Nonce 12B}] \parallel [\text{sender\_id 16B}] \parallel [\text{recipient\_id 16B}] \parallel [\text{seq\_no 8B}] \parallel [\text{ciphertext + tag}]$$

---

### Passo 7: Anti-Replay e Fail-Closed (Recepção)

Quando o Cliente B recebe o frame E2E:
1. **Validação de Sequência (Anti-Replay):** O receptor verifica se o `seq_no` recebido é estritamente maior que o último `seq_recv` registrado para aquele peer ($seq\_no > seq\_recv$). Se for igual ou menor, o frame é rejeitado imediatamente (*replay rejected*), prevenindo ataques onde um invasor reenvia pacotes legítimos capturados anteriormente.
2. **Decifragem e Verificação da Tag (AEAD):** O receptor reconstrói o AAD e chama o decritor AES-GCM. Se qualquer bit do ciphertext, do remetente, do destinatário ou do número de sequência tiver sido adulterado na rede, a tag falha e levanta uma exceção `InvalidTag` (*tampering* detectado).
3. **Atualização do Estado:** Apenas após a verificação bem-sucedida, o `seq_recv` é atualizado.

---

### Passo 8: O Servidor Relay Cego e Ciclo de Vida

- **Roteamento:** O servidor lê o frame E2E recebido, extrai o `recipient_id`, busca a conexão (`writer`) correspondente na tabela `sessions` e reencaminha os bytes **exatamente como recebeu**, sem enxergar o conteúdo.
- **Plano de Controle (Mensagens Administrativas):** O servidor gerencia a entrada, saída e listagem de peers ativos através de mensagens administrativas controladas por seu próprio contador de sequência.
- **Desconexão e Reconexão:** Se um cliente cai, sua sessão é removida de forma segura (*fail-closed*) e os demais clientes são avisados. Se o cliente reconecta, um novo handshake é realizado, gerando um novo `salt_srv` e novas chaves efêmeras, garantindo isolamento total entre sessões.

---

## 4. Tabela Resumo de Termos e Mapeamento nas Aulas

| Termo / Nomeclatura | O que significa no projeto | Onde foi estudado (Pasta `Estudos/`) |
|---------------------|---------------------------|--------------------------------------|
| **`client_id`** | Identificador UUID v4 de 16 bytes do cliente. | Identidade e Sessões |
| **`sk` / `pk`** | Chave Privada (`sk`) e Chave Pública (`pk`). | [[7_Criptografia]] & [[9_Troca de chaves privadas]] |
| **`X25519`** | Curva elíptica usada para o Diffie-Hellman efêmero (ECDHE). | [[9_Troca de chaves privadas]] |
| **`Z_AB`** | Segredo bruto compartilhado computado via ECDH entre dois clientes. | [[9_Troca de chaves privadas]] |
| **`salt_srv`** | Salt gerado pelo servidor no handshake para amarrar a sessão. | [[10_Key Derivation Function]] |
| **`HKDF`** | Função baseada em HMAC para derivar chaves a partir de $Z_{AB}$. | [[10_Key Derivation Function]] |
| **`server.crt` / Pinning** | Certificado autoassinado pinado no cliente ("CA caseira"). | [[11_Assinatura e certificado digital]] |
| **`RSA-PSS`** | Algoritmo de assinatura digital assimétrica usado no handshake. | [[11_Assinatura e certificado digital]] |
| **`AES-128-GCM`** | Cifra simétrica AEAD (Confidencialidade + Integridade + Autenticidade). | [[12_Protocolos de Segurança]] |
| **`AAD`** | Dados associados autenticados no AEAD (remetente, destinatário, seq). | [[12_Protocolos de Segurança]] |
| **`seq_no`** | Contador monotônico por direção para proteção anti-replay. | [[12_Protocolos de Segurança]] |

---

No protocolo, seq_send e seq_recv são contadores mntidos pelo SERVER essenciais para duas garantias fundamentais:
   1. Proteção Anti-Replay: Impedem que um atacante capture um pacote legítimo e o reenvie.
   2. Construção do Nonce (no E2E): O seq_send compõe o nonce do AES-GCM (IV_base ‖ seq_no), garantindo que a regra sagrada do AES-GCM — nunca repetir um par (chave, nonce) — seja
      seguida estritamente.

   * seq_send = 0 (O próximo a enviar):
     - Significa que a primeira mensagem enviada pelo server usará o número de sequência 0. 

   * seq_recv = -1 (O último recebido do CLIENTE):
     - Ele começa em -1 porque nenhuma mensagem foi recebida ainda.


---

1. Assinatura Digital ≠ Criptografia
  Quando o servidor assina o material (pk_S || pk_C || client_id || salt_srv) com sua chave privada (server.key), ele não está cifrando o material para torná-lo secreto. 
   * A assinatura gera apenas uma tag baseada no hash do material.
   * O material original (incluindo o certificado) viaja pela rede em texto claro (plaintext) junto com a assinatura.

  ---

  2. O que realmente é enviado na resposta do Handshake?
  Olhando o código em protocol/handshake.py (create_server_handshake_response), o pacote enviado ao
  cliente tem esta estrutura exata:

  Payload = [Tamanho do Cert] ∥ [server.crt (certificado contendo  pk_S)] ∥ [Tamanho da Assinatura] ∥ [Assinatura RSA-PSS] ∥ [saltₛrv]

