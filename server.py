import asyncio
from typing import TypedDict
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from protocol.framing import send_frame, recv_frame
from protocol.ids import format_client_id
from protocol.keys import deserialize_public_key
from protocol.handshake import (
    load_server_private_key,
    load_server_certificate,
    create_server_handshake_response
)

class SessionData(TypedDict):
    writer: asyncio.StreamWriter
    public_key: X25519PublicKey
    seq_send: int
    seq_recv: int
    salt: bytes

sessions: dict[str, SessionData] = {}

# Carregar chave privada e certificado do servidor no boot
SERVER_PRIV_KEY = load_server_private_key()
with open("certs/server.crt", "rb") as f:
    SERVER_CERT_BYTES = f.read()

# ---------------------------------------------------------------------------------

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Função assíncrona executada para cada cliente."""

    peername = writer.get_extra_info('peername')
    print(f"Nova conexão de {peername}")

    try:
        client_id_str = await registration(reader, writer)

        while True:
            # Recebe o frame do cliente utilizando o leitor de stream
            payload = await recv_frame(reader)
            print(f"Recebido payload de {len(payload)} bytes de {client_id_str}")
            # Devolve o mesmo payload recebido para o cliente (eco)
            await send_frame(writer, payload)

    except asyncio.IncompleteReadError:
        print("Conexão fechada pelo cliente.")
    except (ValueError, Exception) as e:
        print(f"Erro de protocolo / Handshake falhou: {e}")
    finally:
        # Garante o fechamento seguro dos recursos de rede ao finalizar a sessão
        writer.close()
        await writer.wait_closed()

async def registration(reader, writer):
    """Função responsável por registrar o cliente, executar o handshake e armazenar sessão."""
    # Primeiro frame -> registro: client_id (16B) + pk (32B) = 48B
    registration_frame = await recv_frame(reader)
    if len(registration_frame) != 48:
        raise ValueError("Frame de registro inválido")

    client_id_bytes = registration_frame[:16]
    pk_c_bytes = registration_frame[16:]

    client_id_str = format_client_id(client_id_bytes)
    pk_c = deserialize_public_key(pk_c_bytes)

    # Executar handshake: assinar pk_S || pk_C || client_id || salt_srv
    (handshake_response, salt_srv) = create_server_handshake_response(
        SERVER_PRIV_KEY,
        SERVER_CERT_BYTES,
        pk_c_bytes,
        client_id_bytes
    )

    await send_frame(writer, handshake_response)
    print(f"Handshake realizado com sucesso para o cliente {client_id_str} (salt gerado)")

    sessions[client_id_str] = {
            'writer': writer,
            'public_key': pk_c,
            'seq_send': 0,  # número sequencial da próxima mensagem que este cliente vai enviar.
            'seq_recv': -1, # número sequencial da última mensagem válida que este cliente recebeu.
            'salt': salt_srv
        }
    return client_id_str

async def main():
    """Função principal do servidor responsável por inicializar o listener TCP."""

    # Necessariamente o handle precisa ser passado como callback e precisa de reader e writer
    # O próprio asyncio instancia o reader e writer para cada conexão de cliente
    server = await asyncio.start_server(handle_client, '127.0.0.1', 8888)
    print("Servidor iniciado em 127.0.0.1:8888")

    # Mantém o servidor em execução permanente
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())