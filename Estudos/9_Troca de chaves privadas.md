

---

A distribuição de chaves secretas pode ser realizada de diversas maneiras, como: 
- **Troca manual.** 
- **Canais criptografados:** A chave enviada através de um canal de comunicação já criptografado.
- **Protocolos de troca de chaves:** São algoritmos e procedimentos que permitem a troca segura de chaves entre as partes.
### 1. Troca de Chaves Diffie-Hellman 
Foi um dos primeiros exemplos práticos de métodos de troca de chaves implementado dentro do campo da criptografia, tendo sido publicado em 1976.

**Analogia com tintas**
![450](../../attachments/Pasted%20image%2020260923084440.png)![500](../../attachments/Pasted%20image%2020260923084611.png)

1. Alice e Bob concordam em dois **números públicos**: um número primo **p** e um gerador **g**.
2. Alice escolhe uma chave secreta a, e Bob escolhe uma chave secreta b. 
3. Alice calcula **A = g^a mod p** e envia A para Bob.
4. Bob calcula: **B = g^b mod p** e envia B para Alice.
5. Alice calcula S **= B^a mod p** e Bob calcula **S = A^b mod p**

![400](../../attachments/Pasted%20image%2020260923091612.png)
![400](../../attachments/Pasted%20image%2020260923085224.png)

---
### 2. Troca de chaves usando Criptografia de Chave Pública

Usando criptografia asimétrica para fazer a troca de chaves simétrica para comunicação fim a fim.
![](../../attachments/Pasted%20image%2020260923093058.png)
**Geração de Chaves RSA:**
- Alice gera um par de chaves. Uma chave pública e uma chave privada.
**Criptografia da Chave Secreta:**
- Bob gera uma chave simétrica que eles usarão para a comunicação. 
- Ele então criptografa essa chave simétrica usando a chave pública de Alice. Assim somente a Alice pode descriptografar com a chave privada.

---

**PROBLEMA DOS DOIS MÉTODOS: AUTENTICAÇÃO!**
Nenhum dos métodos de troca de chaves puros discutidos oferece autenticação. Isso significa que Alice e Bob não têm certeza de que estão realmente conversando um com o outro, Sem autenticação, um ataque de Man-in-the-Middle é possível.
- **Soluções**: Certificados digitais e infraestruturas de chave pública (PKI), Assinatura digita.

---

**Criptografia:** 
- Garante: CONFIDENCIALIDADE e AUTENTICIDADE (se chaves compartilhadas com autenticidade)
- N garante: INTEGRIDADE, AUTENTICIDADE e NÃO REPÚDIO

**Função HASH:**
- Garante: INTEGRIDADE
- N garante: CONFIDENCIALIDADE, AUTENTICIDADE e NÃO REPÚDIO.

**MAC**
- Garante: INTEGRIDADE e AUTENTICIDADE (se chaves compartilhadas com autenticidade)
- N garante: CONFIDENCIALIDADE e NÃO REPÚDIO.