

---

### Q2: O que são "Fingerprints"?
* **Definição:** É o resultado da aplicação de uma função **Hash (SHA-256)** ([[8_Função Hash e Mac]]) sobre uma chave pública (ou certificado), geralmente truncado em seus primeiros bytes e exibido em formato hexadecimal (ex: `a3f9b21c`).
* **Por que é seguro logar?** Pela propriedade de **resistência à primeira inversão (unidirecionalidade)** do Hash, é computacionalmente impossível reverter o hash para descobrir a chave pública original. Isso permite que você coloque `[LOG] Chave registrada: a3f9b21c...` no terminal para depuração sem violar a segurança ou vazar dados sensíveis.

---

### Q3: O `AES-128-GCM` usa Encrypt-then-MAC (EtM)? Envolve Hash? Qual a diferença entre "AES-GCM" e "AES-128-GCM"?
* **AES-GCM vs AES-128-GCM:** São exatamente a mesma coisa. O "128" especifica o tamanho da chave simétrica em bits (16 bytes), que é o padrão exigido pelo TP.
* **Relação com EtM ([[12_Protocolos de Segurança]]):**
  - Nas três composições clássicas (*MtE*, *E&M*, *EtM*), a literatura aponta **Encrypt-then-MAC** como a mais segura, pois garante que a verificação de integridade/autenticidade (*MAC/Tag*) ocorra **antes** de qualquer tentativa de decifragem, bloqueando ataques como *Padding Oracle*.
  - O **AES-GCM** é um modo **AEAD** (*Authenticated Encryption with Associated Data*). Ele não é uma gambiarra montada à mão de Cifra + HMAC; ele foi construído matematicamente para prover confidencialidade e autenticidade simultaneamente de forma otimizada, cumprindo a garantia de segurança do padrão EtM por design.
* **Onde entra o Hash no GCM?**
  - O AES-GCM utiliza internamente uma função de hash baseada em aritmética de corpos finitos chamada **GHASH** para calcular a tag de autenticação sobre o texto cifrado e os dados associados (AAD).
  - Além disso, o protocolo utiliza **SHA-256** no **HKDF** (derivação de chaves) e nas **Assinaturas RSA-PSS**.

---

### Q4: Como o RSA-PSS garante a autenticidade durante o handshake?
* **O problema:** Quando o cliente recebe a chave pública `pk_S` do servidor, como ele sabe que ela pertence ao servidor legítimo e não a um invasor no meio da rede (MITM)?
* **A solução (Assinatura Digital - [[11_Assinatura e certificado digital]]):**
  1. O servidor possui a chave privada RSA (`server.key`).
  2. No handshake, o servidor assina o resumo criptográfico (hash SHA-256) do material da sessão:
     $$\text{Material} = pk_S \parallel pk_C \parallel \text{client\_id} \parallel salt\_srv$$
     utilizando `server.key`.
  3. O cliente recebe essa assinatura e a verifica utilizando a chave pública extraída do certificado do servidor (`server.crt`).
  4. **Por que isso prova autenticidade?** Pela propriedade da criptografia assimétrica, **apenas** quem detém a chave privada correspondente (`server.key`) poderia ter gerado um conjunto de bytes válido para aquele hash específico. Se um invasor tentou alterar o `pk_C` no meio do caminho, o hash muda, a verificação falha (`InvalidSignature`) e o cliente se desconecta imediatamente.

---

### Q5: Como um certificado autoassinado pode ser seguro no nosso projeto?
* **O contexto da Web vs. Sistema Fechado:**
  - Na Web aberta, você acessa milhões de sites desconhecidos; por isso você precisa de uma hierarquia global de Autoridades Certificadoras (CAs como Let's Encrypt ou DigiCert) pré-instaladas no seu navegador.
  - No trabalho prático (TP3), o sistema é **fechado e controlado**: existe um único servidor conhecido.
* **O Mecanismo de Pinning:**
  - O certificado `server.crt` é **gerado uma vez** e uma cópia dele é colocada diretamente no diretório do cliente (*pinning* / fixação de certificado).
  - Quando o cliente conecta, ele compara byte a byte o certificado recebido do servidor com o arquivo local pinado (`pinned_cert_path`).
  - **Por que é seguro?** Se um atacante tentar injetar um certificado falso assinado por uma CA maliciosa ou por ele mesmo, o cliente rejeitará a conexão porque o certificado recebido **não é idêntico** ao arquivo pinado no disco. A "CA" do sistema é o próprio arquivo de certificado distribuído no setup inicial.

---

## 3. O Fluxo Passo a Passo Completo

### Passo 1: Conexão TCP e Framing (Prefixo de 4 Bytes)
- **Problema:** O TCP trata dados como um fluxo contínuo de bytes sem demarcação de mensagens.
- **Solução:** Antes de enviar qualquer payload (handshake, registro ou frame E2E), o remetente envia **4 bytes em big-endian** (`struct >I`) indicando o tamanho exato. O receptor lê o prefixo, sabe quantos bytes esperar e consome exatamente esse bloco (`readexactly`), evitando mensagens grudadas ou truncadas.

### Passo 2: Identidade (`client_id` UUID v4)
- Cada cliente gera localmente um identificador de 16 bytes baseado em **UUID v4** no seu primeiro boot, servindo como seu endereço unívoco na rede.

### Passo 3: Registro com Chave Efêmera X25519
- O cliente gera seu par X25519 efêmero (`sk_C`, `pk_C`).
- Envia ao servidor: `client_id` (16B) + `pk_C` (32B, cru em `Encoding.Raw`).
- O servidor registra na tabela interna: `sessions[client_id] = {writer, pk_C, seq_send=0, seq_recv=-1, salt}`.

### Passo 4: Handshake Autenticado (RSA-PSS + Pinning)
1. O servidor gera `salt_srv` (16 bytes aleatórios).
2. O servidor monta o material: $\text{Material} = pk_S \parallel pk_C \parallel \text{client\_id} \parallel salt\_srv$.
3. O servidor assina com RSA-PSS(SHA-256) usando `server.key`.
4. O servidor envia: `[tamanho cert || server.crt || tamanho assinatura || assinatura || salt_srv]`.
5. O cliente valida:
   - Compara o `server.crt` recebido com o certificado pinado local (`fail-closed` se divergir).
   - Verifica a assinatura digital usando a chave pública do certificado sobre o material remontado.
   - Extrai o `salt_srv`.

### Passo 5: Derivação de Chaves Fim a Fim (`Z_AB` + HKDF)
1. **O Segredo `Z_AB` (ECDH):** Quando o Cliente A recebe a chave pública do Cliente B (`pk_B`), ele executa a troca de Diffie-Hellman baseada em curvas elípticas:
   $$Z_{AB} = \text{ECDH}(sk_A, pk_B)$$
   O Cliente B faz o mesmo com `pk_A`. Ambos chegam exatamente ao **mesmo** segredo bruto $Z_{AB}$, sem que o servidor jamais tenha acesso a ele.
2. **Derivação com HKDF ([[10_Key Derivation Function]]):**
   - O segredo $Z_{AB}$ entra como IKM no HKDF-SHA256 junto com o `salt_srv`.
   - Gera-se duas chaves simétricas de 16 bytes rotuladas: `Key_A2B` e `Key_B2A`.
3. **Ordem Determinística:** Ordenando os `client_id` como bytes, o menor ID é "A" e o maior é "B", garantindo que ambos os lados saibam qual chave usar para enviar (`key_send`) e qual usar para receber (`key_recv`).
4. $Z_{AB}$ é apagado da memória imediatamente após a derivação.

### Passo 6: Cifragem E2E (AES-128-GCM + AAD + Nonce)
Para enviar uma mensagem:
1. **Nonce (12B):** $IV_{base} \text{ (4 bytes aleatórios)} \parallel seq\_no \text{ (8 bytes big-endian)}$.
2. **AAD (Dados Associados):** $sender\_id \parallel recipient\_id \parallel seq\_no$.
3. **Cifragem:** `AESGCM(key_send).encrypt(nonce, plaintext, aad)` produz o `ciphertext + tag`.
4. **Frame:** $[\text{Nonce 12B}] \parallel [\text{sender\_id 16B}] \parallel [\text{recipient\_id 16B}] \parallel [\text{seq\_no 8B}] \parallel [\text{ciphertext + tag}]$.

### Passo 7: Anti-Replay e Fail-Closed na Recepção
Ao receber um frame E2E:
1. **Anti-Replay:** Verifica se $seq\_no > seq\_recv$ para aquele peer. Se for menor ou igual, rejeita (`replay rejected`).
2. **Decifragem & Integridade:** Reconstrói o AAD e descriptografa. Se houver adulteração, a tag falha (`InvalidTag`).
3. **Atualização:** Atualiza o `seq_recv` apenas após sucesso absoluto.

### Passo 8: Servidor Relay Cego e Ciclo de Vida
- O servidor encaminha os frames E2E verbatim com base no `recipient_id`, gerenciando conexões simultâneas com `asyncio.Lock` e isolando exceções por tarefa (*fail-closed*).

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
