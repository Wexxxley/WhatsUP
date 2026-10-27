


---
### 1. Função Hash

Função matemática **determinística** que comprime uma string em uma string de tamanho fixo. 
- É unidirecional
- Não usa chaves.

![450](../../attachments/Pasted%20image%2020260923074834.png)
**Requisitos:** Seja H(x) uma função Hash:
- H pode ser aplicado a um bloco de dados de qualquer tamanho.
- H produz uma saída de comprimento fixo. 
- H(x) é relativamente fácil de calcular para qualquer x. 
- **Resistência a Primeira Inversão (unidirecional):** Para qualquer valor de y dado, é computacionalmente inviável encontrar x tal que H(x) = y. 

- **Resistência a Segunda Inversão:** Dado uma entrada já conhecida ($x$) e o seu respectivo resultado de _hash_ ($H(x)$). O conceito garante que é computacionalmente impraticável forjar um novo dado ($y$, sendo $y \neq x$) que resulte no mesmo _hash_ gerado pelo dado original. Isso impossibilita que um invasor substitua um arquivo legítimo por um arquivo malicioso sem que a validação de integridade aponte a adulteração.
	
- **Resistência a Colisões:** A propriedade estipula que é computacionalmente impraticável encontrar quaisquer duas entradas arbitrárias e distintas ($x$ e $y$) que gerem idêntico valor de _hash_ $H(x) = H(y)$ Trata-se da exigência matemática mais rigorosa de uma função de _hash_, cujo objetivo é impedir ataques onde o agente malicioso gera simultaneamente um documento autêntico e um fraudulento.

**Aplicações:**
- **integridade**: confirmar se um arquivo sofreu alguma modificação durante a transmissão. Calcula-se o valor de hash na origem e recalcula-se o valor no destino; a correspondência dos resultados comprova que o dado permaneceu intacta.
- **Proteção de Senhas**: SOs e aplicações web armazenam exclusivamente o valor de hash das credenciais de acesso. Durante o processo de autenticação, o sistema processa a senha inserida e compara o hash resultante com o registro do banco de dados.
- **Assinatura digital** No processo formal de assinatura, extrai-se o _hash_ do conteúdo integral de um documento e cifra-se estritamente este valor utilizando a chave privada do signatário. Este método otimiza o processamento computacional e atesta a validade jurídica da comunicação (autenticidade e não-repúdio), assegurando que o arquivo atestado é exatamente o mesmo que gerou a assinatura.

---
### 2. MAC

A Confidencialidade é abordada por Criptografia, mas não garante **autenticidade** e **integridade**. 

**MAC (Message Authentication Code):** Bloco de dados gerado por um algoritmo MAC e uma chave secreta. Anexado a uma mensagem para permitir que o receptor verifique a **integridade** e **autenticidade** da mensagem.
- Também conhecido como "cryptographic checksum" ou "keyed hash".
![](../../attachments/Pasted%20image%2020260923080410.png)
O remetente possui uma mensagem (M) e uma chave secreta compartilhada (K).
- Aplica uma função MAC na mensagem (M) e na chave (K).
- Envia a mensagem (M) e o MAC gerado para o receptor.
- O receptor possui a mesma chave secreta compartilhada.
- Gera um novo MAC a partir da mensagem recebida e da chave e compara.

**Requisitos**
- **Resistência a colisões:** É difícil encontrar duas mensagens diferentes que gerem mesmo MAC.
- **Resistência a ataques de força bruta** 
- **Dependência da chave secreta:** O MAC deve ser sensível a pequenas mudanças na chave. 
- **Dependência da mensagem:** O MAC deve ser sensível a pequenas mudanças na mensagem.

**HMAC**: consiste na aplicação de uma função de hash ao MAC. 

- K = Chave
- M =Mensagem
- H = Função hash
- Opad = prenchimento externo, utilizado para modificar a chave.
- Ipad = prenchimento interno, utilizado para modificar a chave.![](../../attachments/Pasted%20image%2020260923081005.png)![](../../attachments/Pasted%20image%2020260923081021.png)
**XOR (Ou Exclusivo)**: Na sua fundação, processa apenas dois bits. Se diferentes 1, se iguais 0.
- Para aplicar o XOR a blocos completos de dados, os dois blocos em operação necessitam possuir um tamanho idêntico. O sistema alinha as duas sequências de bytes e executa o cálculo XOR sequencialmente nos pares de bits que partilham a mesma posição 

**Aplicações**
- **Protocolos de Comunicação Segura**: O protocolo IPsec (Internet Protocol Security) emprega o mecanismo para atestar a autenticação dos pacotes IP transmitidos na rede. Em paralelo, os protocolos TLS e SSL (Transport Layer Security / Secure Sockets Layer) utilizam-no para garantir a autenticação de mensagens trocadas durante sessões web seguras.
- **Integridade de Dados e Sistemas**: O mecanismo é aplicado na verificação de integridade de arquivos, atestando se a estrutura original de um arquivo sofreu modificação após o seu armazenamento ou download. 