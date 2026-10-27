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