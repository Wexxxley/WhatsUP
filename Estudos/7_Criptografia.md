
#Concluded 

---

Criptografia é uma forma de garantir a CONFIDENCIALIDADE. Transforma o texto simples em texto ilegível, utilizando algoritmos matemáticos.

A criptografia em si garante apenas a **confidencialidade**.
- **Autenticação:** É garantida pelo uso de assinaturas digitais ou certificados digitais, que provam a identidade real de quem enviou a informação.
- **Não-repúdio:** Também é assegurado pela assinatura digital, impedindo que o emissor negue posteriormente a autoria da mensagem enviada.

**Texto claro:** Mensagem original a ser enviada.
**Texto cifrado:** Texto claro codificado.
**Cifragem/Criptografia:** Processo de converter texto claro em texto cifrado. 
**Decifragem/Decriptografia:** Processo de restaurar o texto claro a partir do texto cifrado. 
**Sistema Criptográfico/Cifra:** Esquema utilizado para a realização de criptografia.
**Criptoanálise:** Técnicas para decifrar uma msg, sem conhecimento dos detalhes da criptografia.
**Criptologia**: consiste nas áreas da criptografia e criptoanálise, juntas.

Os sistemas de Criptografia são caracterizados em três dimensões diferentes:
1. **Modo como texto claro é processado**: 
	1. Cifra de Bloco: Mensagem a ser criptografada é processada em blocos de k bits.
	2. Cifra de Fluxo: Criptografam um texto claro elemento por elemento.
2. **Tipos de operações utilizadas para transformar texto claro em texto cifrado**:
	1. Cifras de Substituição
	2. Cifras de Transposição
	3. Sistemas de Produto
	4. ...
3. **Tipos de criptografia - Número de chaves utilizadas**:
	1. Criptografia Simétrica, de chave única, de chave secreta ou convencional.
	2. Criptografia Assimétrica, de duas chaves ou de chave pública

---
### 1. Cifras de Substituição
Cada elemento no texto claro (bit, letra, grupo de bits, letras) é mapeado em outro elemento. 
#### 1.1 Cifra de cesar
Substituição Monoalfabética.
Chave: Número do deslocamento
![200](../../attachments/Pasted%20image%2020260917164210.png)
#### 1.2 Cifra de playfair
Cifra de Blocos.
Chave = palavra.
- Bloco 5x5
- Troca W por V
- Completa na ordem e não repete as letras

 O remetente e o destinatário precisma decidir 3 regras.![300](../../attachments/Pasted%20image%2020260917164330.png)
#### 1.3 Cifra de Vigenère
Cifra Polialfabética![](../../attachments/Pasted%20image%2020260917172013.png)

---
### 2. Cifras de Transposição
Realiza algum tipo de permutação nas letras do texto claro. 
#### 2.1 Rail Fence
Texto claro escrito como uma sequência de diagonais com profundidde x.
![450](../../attachments/Pasted%20image%2020260923070706.png)
#### 2.2 Transposição colunar
Escreve a mensagem em um retângulo, linha por linha, e ler a mensagem coluna por coluna, mas permutar a ordem das colunas antes
![](../../attachments/Pasted%20image%2020260923071738.png)

---
### 3. Criptografia de chave simétrica

- A mesma chave (Ks) é compartilhada entre Bob e Alice.
- Como combinar sobre a chave de forma segura? 
![](../../attachments/Pasted%20image%2020260923071916.png)
- **Criptografia Fim a Fim**: Modelo de comunicação para que a informação seja encriptada exclusivamente no dispositivo do emissor e apenas decriptada no dispositivo do  destinatário.
	- Usado em apps de mensageria (WhatsApp), email, videoconferência corporativas, etc.
	- **Chave Assimétrica**: Executado apenas no estabelecimento inicial da conexão. Os sistemas utilizam os pares de chaves públicas e privadas para autenticar os participantes e permitir a negociação e a troca segura de uma chave secreta provisória.
	- **Criptografia Simétrica**: Concluída a troca inicial, o tráfego contínuo de dados passa a ser encriptado e decriptado exclusivamente por cifras simétricas. Os algoritmos simétricos executam o processamento com velocidade superior à criptografia assimétrica. Isso viabiliza a transmissão encriptada em tempo real de grandes volumes de dados.

---
### 4. Criptografia de chave assimétrica

- Chave de criptográfia pública conhecida por todos. 
- Chave de decriptação privada conhecida apenas pelo receptor.
- Para haver a comunicação entre os dois, ambos precisam gerar chaves públicas e privadas.
- Os algoritmos são pesados
![](../../attachments/Pasted%20image%2020260923073035.png)
**Requisitos**
- Ser computacionamente fácil gerar um par de chaves.
- Ser computacionalmente fácil gerar um texto cifrado, através de um chave pública. 
- Ser computacionalmente fácil decriptografar o texto cifrado, usando a chave privada. 
- Ser inviável determinar a chave privada, conhecendo a chave pública. 
- Ser inviável recuperar a mensagem original, conhecendo a chave pública e o texto cifrado. 
- As duas chaves podem ser aplicadas em qualquer ordem.

Embora a chave pública possa ser transmitida abertamente, o desafio consiste na **autenticação** e **verificação de titularidade da chave**. Para contornar essa vulnerabilidade, adota-se uma Infraestrutura de Chaves Públicas (ICP/PKI) baseada em Certificados Digitais emitidos por Autoridades Certificadoras.

**Criptografia com a Chave Privada**: A criptografia de uma mensagem com a chave privada não tem o objetivo de prover **confidencialidade**, mas sim de garantir a **autenticidade** e **não-repúdio**.
- Quando o emissor cifra um dado com a sua chave privada, qualquer pessoa na rede pode decriptá-lo utilizando a chave pública. O sucesso dessa decriptação prova duas coisas: 
	1. Que a mensagem foi originada pelo detentor da chave privada.
	2. Que o conteúdo não foi adulterado durante a transmissão.

**RSA (Rivest-Shamir-Adleman)**: É um algoritmo assimétrico cuja segurança deriva da extrema dificuldade computacional de fatorar grandes números primos. 

**ECC (Criptografia de Curva Elíptica)**: É um algoritmo assimétrico fundamentado na matemática de curvas elípticas sobre campos finitos. A sua superioridade técnica reside em fornecer o mesmo nível de segurança criptográfica do RSA com chaves drasticamente menores (ex: 256 bits).

