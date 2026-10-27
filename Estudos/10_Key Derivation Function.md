
#Concluded 

---
### 1. Armazenamento de senhas

Antigamente se armazenava as senhas diretamente no db.

Depois começou a se usar funções hash, que são:
- Determinísticas.
- Possuem efeito avalanche.
- São unidirecionais.![](../../attachments/Pasted%20image%2020261013123838.png)
**Problema**: esses algoritmos são rápidos demais. Existem sites que disponibilizam senhas em plaintext vazadas atualizadas anualmente. Com essa lista de senhas, o hacker consegue criar uma **tabela precomputada de senha e hash.** Quando um db vaza com o hash da sua senha o hacker compara o seu hash com o hash da tabela precomputada, podendo, assim, encontrar uma correspondência e encontrar sua senha real.
![](../../attachments/Pasted%20image%2020261013124328.png)
Posteriormente, possou-se a usar salt.![](../../attachments/Pasted%20image%2020261006125027.png)![](../../attachments/Pasted%20image%2020261013125131.png)
O objetivo é evitar a reutilização de trabalho (tabela precomputada). PARA CADA senha da tabela precomputada ele vai ter que concatenar com o salt, gerar o hash e comparar com o hash da tabela vazada. 

>Mesmo assim, como o hash é muito rápido o hacker ainda pode conseguir.

---
### 2. Key Derivation Function

São funções CPU HARD, ou seja,  são lentos de forma proposital. O salt já é incluído nesses algorítmos.

**Iterância:** quantas vezes o algorítmo vai ser rodado.
![400](../../attachments/Pasted%20image%2020261006123035.png)![](../../attachments/Pasted%20image%2020261006125626.png)
![450](../../attachments/Pasted%20image%2020261006125954.png)
Como o algorítimo é lento, torna inviável fazer o hash e a comparação com todos elementos da tabela precomputada.

Porém, existe um problema, o paralelismo. Aumentando muito a chance de encontrar senhas similares.
![400](../../attachments/Pasted%20image%2020261006130441.png)![400](../../attachments/Pasted%20image%2020261006130601.png)

Ai que surgiu o ARGON2. Ele foca em usar muita memória ram para cada iteração, impedindo que as GPUs usem muito paralelismo.![](../../attachments/Pasted%20image%2020261006130915.png)
![](../../attachments/Pasted%20image%2020261006131144.png)
Para dificultar mais ainda a vida do hacker você pode usar uma PEPPER. Uma string salva no seu .env usada para concatenar com a senha do user e depois aplicado o Argon2
