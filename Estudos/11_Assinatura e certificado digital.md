
#Concluded 

---
### 1. Assinatura digital

Na assinatura digital, bob usa sua chave privada para criptografar uma mensagem. Alice, e qualquer outro, usa a chave pública para garantir que quem mandou a mensagem foi Bob.

Essa ideia simples já garante:
- Autenticação
- Integridade: se alguém alterar a mensagem, a verificação falha.
- Não-repúdio.![](../../attachments/Pasted%20image%2020261006160420.png)
1. h = H(m): hash da mensagem.
2. s = assina(h, Kpriv): assina só o hash
3. Envia (m, s)

Note que a ideia é a mesma do MAC. A diferença é que no MAC é usado uma chave simétrica. Na assinatra digital é usado uma chave assimétrica.
![](../../attachments/Pasted%20image%2020261006160740.png)

---
### 2. Distribuição de chaves públicas

Ok, mas como garantir que a chave pública é realmente de Bob?

> A assinatura prova "quem tem a chave privada correspondente a esta chave pública assinou" e **não** "Bob assinou". 

**Mecanismo 1: Autoridade de chave pública**: Uma entidade confiável mantém uma tabela. Você registra sua chave com prova de identidade; quem quiser falar com você consulta o diretório.
- **Ponto único de falha**: se o diretório for violado, o atacante troca as chaves e se passa por todos ao mesmo tempo.

**Mecanismo 2: Certificado Digital:** Em vez de consultar a autoridade toda vez, a autoridade assina o vínculo uma única vez.
- CA (Certificate Authority) assina UMA vez: cert_Bob = Kpriv_CA( "Bob", Kpub_Bob )
- Alice recebe cert_Bob.
- Alice verifica com a Kpub da CA.

O certificado é uma prova autocontida que viaja junto com a chave pública. Quem verifica só precisa da chave pública da CA, que no HTTPS já vem pré-instalada no navegador; no ICP-Brasil é a AC-Raiz.

>[!tip]
Certificado = uma vez por relação.
Assinatura = a cada mensagem.

Na primeira interação![](../../attachments/Pasted%20image%2020261006164033.png)

Quem emite os Certificados Digitais? As Autoridades Certificadoras (CA). O titular do certificado pode enviá-lo aos destinatários de sua mensagem, que, para validá-lo, devem contatar a Autoridade Certificadora, emissora do certificado.
![](../../attachments/Pasted%20image%2020261006164249.png)
![450](../../attachments/Pasted%20image%2020261006164324.png)
![450](../../attachments/Pasted%20image%2020261006164439.png)

---
### 3. Infraestrutura de chave pública - ICP ou PKI

Conjunto de hardware, software, pessoas, políticas e procedimentos necessários para criar, gerenciar, armazenar, distribuir e revogar certificados digitais com base na criptografia assimétrica.

**Padrão internacional X.509**:  Define a estrutura e o formato dos cetificados digitais. 
   - Versão do padrão X.509.
   - Número de série (identificador único emitido pela CA).
   - Algoritmo de assinatura (ex: sha256WithRSAEncryption).
   - Emissor (Issuer) (quem emitiu o certificado).
   - Período de validade (notBefore e notAfter).
   - Sujeito (Subject) (a entidade dona da chave pública, ex: CN=tp3-server).
   - Chave pública da entidade (com o algoritmo correspondente, ex: RSA).
   - Assinatura digital (feita pelo emissor sobre todos os campos acima).



