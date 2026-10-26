# WhatsUp — Sistema de Mensageria Segura Multi-Cliente (E2E)

Trabalho Prático 3 (TP3) — Disciplina de Segurança da Informação  
**Professor:** Michel Sales  

---

## Visão Geral

O **WhatsUp** é uma aplicação de mensageria segura multi-cliente com criptografia ponta-a-ponta (**E2E**). O servidor atua estritamente como um **relay/rendezvous cego**, sem capacidade de decifrar o conteúdo das mensagens trocadas entre os clientes. Cada cliente realiza um handshake autenticado com o servidor para registrar sua chave pública efêmera e receber as chaves públicas dos demais participantes.

### Garantias de Segurança
1. **Confidencialidade:** As mensagens são cifradas de ponta a ponta utilizando **AES-128-GCM (AEAD)**.
2. **Integridade:** Qualquer adulteração no tráfego é detectada pela tag de autenticação GCM (`InvalidTag`).
3. **Autenticidade:** O servidor é autenticado perante os clientes utilizando **RSA-PSS com SHA-256** e certificado autoassinado pinado (`certs/server.crt`).
4. **Sigilo Perfeito (Forward Secrecy):** Obtido através do uso de chaves efêmeras **X25519 (ECDHE)** a cada sessão.
5. **Anti-Replay:** Proteção contra reenvio de mensagens garantida por contadores monotônicos por direção (`seq_no > seq_recv`).

---

## Estrutura do Projeto

```
WhatsUp/
├── server.py               # Servidor TCP assíncrono (relay cego e gerenciamento de sessões)
├── client.py               # Cliente de mensageria e testes E2E
├── protocol/
│   ├── framing.py          # Delimitação de frames com prefixo de 4 bytes (big-endian) e limites
│   ├── ids.py              # Manipulação de UUID v4 binário (16 bytes) e formatação
│   ├── handshake.py        # Handshake autenticado (RSA-PSS com SHA-256 e server pinning)
│   ├── keys.py             # Pares X25519, serialização raw e fingerprints
│   ├── crypto.py           # Cifragem AES-128-GCM (nonce, AAD), HKDF-SHA256 e anti-replay
│   └── admin.py            # Estruturas de controle administrativo
├── tools/
│   └── generate_certificate.py # Ferramenta one-off para gerar server.key e server.crt
├── certs/
│   ├── server.crt          # Certificado público do servidor (pinado nos clientes)
│   └── server.key          # Chave privada do servidor (estritamente confidencial / .gitignore)
├── tests/
│   ├── test_handshake.py   # Testes unitários do handshake e assinaturas RSA-PSS
│   ├── test_crypto.py      # Testes unitários de derivação de chaves e AEAD AES-GCM
│   └── test_integration.py # Testes de integração cobrindo a matriz da rubrica (T1 a T4)
└── README.md               # Documentação completa
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

### 5. Executando a Suíte de Testes
Para rodar todos os testes unitários e de integração (incluindo os testes da rubrica):
```bash
python3 -m unittest discover tests
```

---

## Matriz de Aceitação e Testes Obrigatórios (Etapa 9)

| Teste | Descrição / Entrada | Resultado Esperado | Garantia Demonstrada |
|---|---|---|---|
| **T1** | Dois clientes honestos trocam mensagens E2E. | Mensagem decifrada corretamente no destino. | Confidencialidade + Integridade + Autenticidade |
| **T2** | Modificação de 1 bit no ciphertext ou no AAD (`recipient_id`). | Rejeição imediata com erro `tag mismatch` (`InvalidTag`). | Integridade / Anti-forgery |
| **T3** | Reenvio de um frame válido já entregue (`seq_no` duplicado). | Rejeição imediata com log `replay rejected`. | Proteção Anti-Replay (`seq_no` monotônico) |
| **T4** | Envio de um frame excedendo o tamanho máximo permitido (`MAX_FRAME_SIZE`). | Desconexão segura do cliente/servidor (fail-closed) sem crash. | Robustez de Framing e Tratamento de Erros |

---

## Política de Segurança e Auditoria de Logs (Etapa 10)

O sistema cumpre estritamente a política de privacidade e segurança exigida:
- **O que NUNCA é logado:** Chaves privadas (RSA ou X25519), segredos compartilhados `Z`, salt em texto claro, nonces e conteúdo de mensagens (plaintexts).
- **O que é permitido e logado:** Eventos de conexão e desconexão, `client_id` (formatado), tamanhos de mensagens, razões de rejeição (`tag mismatch`, `replay rejected`) e fingerprints de chaves públicas (`SHA-256(pk)` truncado em 8 bytes hex).
- **Filosofia Fail-Closed:** Qualquer violação de protocolo (tag inválida, sequência repetida, framing inválido) encerra imediatamente a sessão afetada de forma segura.

---

## Decisões de Projeto (Anexo B)

1. **Seleção de "A" e "B" no ECDH:** Para qualquer par, os `client_id` são ordenados como bytes. O menor ID é definido como "A" e o maior como "B", garantindo que ambos os lados derivem deterministicamente as mesmas chaves nas direções corretas (`Key_A2B` e `Key_B2A`).
2. **Contador de Sequência (`seq_send`):** Incrementado **após** a cifragem com o valor atual (iniciando em 0), compatível com o estado inicial `seq_recv = -1` do receptor.
3. **Servidor Cego (Blind Relay):** O servidor atua apenas como roteador de bytes. Ele não possui acesso às chaves E2E e não consegue decifrar as mensagens.
4. **Isolamento de Conexões:** Cada cliente é tratado em uma `asyncio.Task` independente protegida por `asyncio.Lock`, garantindo que falhas ou desconexões em uma sessão não afetem as demais.
