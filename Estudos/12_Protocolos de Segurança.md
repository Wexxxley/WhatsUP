

---
### 1. MAC-then-Encrypt (MtE)

1. **MAC:** mac do textplain
2. **Cifragem:** criptografia do bloco (m, mac(m))

- Como a descriptografia ocorre antes da verificação do MAC, um atacante consegue explorar o comportamento do sistema perante erros de preenchimento. 
### 2. Encrypt-and-MAC (E&M)

- **Cifragem:** do textplain
- **MAC:** do textplain

- Como o MAC protege o texto plano e não o texto cifrado, o sistema pode ficar vulnerável a ataques de texto cifrado.
### 3. Encrypt-then-MAC (EtM)

- **Cifragem**: do textplain
- **MAC**: do texto cifrado

- É a abordagem mais segura entre as três composições clássicas. Protege contra ataques de oráculo de preenchimento porque a validação do MAC ocorre integralmente antes de qualquer tentativa de descriptografia. Caso o texto cifrado seja adulterado, ele é rejeitado imediatamente.
![300](../../attachments/Pasted%20image%2020261014083340.png)
---

### **1. Ataque Padding Oracle**

Explora erros de preenchimento em modos de cifra de bloco como CBC (Cipher Block Chaining).
- Em CBC, os dados são divididos em blocos e, se o último bloco for menor que o tamanho necessário, ele é preenchido.
- Quando um servidor descriptografa uma mensagem, ele verifica se o padding está correto. Se o padding estiver incorreto, o servidor retorna um erro específico.
- Um atacante pode enviar mensagens modificadas e observar as respostas do servidor para deduzir o conteúdo original, byte por byte.
### 2. Ataque de Forgery

Esse ataque ocorre quando um sistema não autentica corretamente os dados criptografados, permitindo que um atacante modifique ou falsifique mensagens sem ser detectado. 
- Se o MAC for verificado após a descriptografia (como em MtE), o atacante pode explorar falhas no modo de cifra para inserir comandos maliciosos.

---
### 1. AEAD - Authenticated Encryption with Associated Data

Garante simultaneamente:
- Confidencialidade: os dados são criptografados e não podem ser lidos por terceiros.
- Integridade: qualquer modificação nos dados pode ser detectada.
- Autenticidade: garante que os dados vieram de uma fonte confiável.

Um algoritmo AEAD também combina criptografia simétrica e MAC. Além disso, permite incluir dados associados (como cabeçalhos de protocolo) que não são criptografados, mas são autenticados. Se forem alterados, a verificação falha.

**Exemplos de algoritmos AEAD:**
- AES-GCM: muito usado em TLS 1.2 e 1.3.
