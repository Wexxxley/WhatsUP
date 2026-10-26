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
    client_id_bytes: bytes
    pk_bytes: bytes
    seq_send: int
    seq_recv: int
    salt: bytes

sessions_lock = asyncio.Lock()
sessions: dict[str, SessionData] = {}

# Carregar chave privada e certificado do servidor no boot
SERVER_PRIV_KEY = load_server_private_key()
with open("certs/server.crt", "rb") as f:
    SERVER_CERT_BYTES = f.read()

# ---------------------------------------------------------------------------------

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Função assíncrona executada para cada cliente (isolada por task)."""

    peername = writer.get_extra_info('peername')
    print(f"Nova conexão de {peername}")
    client_id_str = None
    client_id_bytes = None

    try:
        client_id_str, client_id_bytes, pk_c_bytes = await registration(reader, writer)

        while True:
            # Recebe o frame do cliente utilizando o leitor de stream
            payload = await recv_frame(reader)

            # Se for frame de anúncio de peer (48 bytes), ignorar ou tratar
            if len(payload) == 48:
                continue

            # Roteamento E2E (blind relay): se for frame E2E (>= 68 bytes), encaminhar para o recipient_id
            if len(payload) >= 68:
                recipient_id_bytes = payload[28:44] # recipient_id está nos bytes 28 a 44
                recipient_id_str = format_client_id(recipient_id_bytes)
                
                async with sessions_lock:
                    if recipient_id_str in sessions:
                        recipient_writer = sessions[recipient_id_str]['writer']
                        await send_frame(recipient_writer, payload)
                        print(f"[Relay] Frame E2E encaminhado de {client_id_str} para {recipient_id_str} ({len(payload)} bytes)")
                    else:
                        print(f"[Relay] Destinatário {recipient_id_str} não encontrado.")
            else:
                # Devolve o mesmo payload recebido para o cliente (eco de teste)
                await send_frame(writer, payload)

    except asyncio.IncompleteReadError:
        print(f"Conexão fechada pelo cliente {client_id_str or peername}.")
    except (ValueError, Exception) as e:
        print(f"Erro de protocolo / exceção na sessão de {client_id_str or peername}: {e}")
    finally:
        if client_id_str and client_id_bytes:
            async with sessions_lock:
                if client_id_str in sessions:
                    del sessions[client_id_str]
                
                # Notificar pares restantes sobre a saída deste cliente (mensagem administrativa de saída)
                leave_frame = client_id_bytes + b"\x00" * 32
                for other_id_str, other_data in sessions.items():
                    try:
                        await send_frame(other_data['writer'], leave_frame)
                    except Exception:
                        pass

            print(f"Cliente {client_id_str} removido das sessões e peers notificados.")

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

    async with sessions_lock:
        # 1. Enviar contagem de peers existentes e os dados de cada peer para o novo cliente
        num_peers = len(sessions)
        await send_frame(writer, num_peers.to_bytes(4, 'big'))

        for existing_id_str, existing_data in sessions.items():
            # Envia peer existente para o novo cliente
            peer_info = existing_data['client_id_bytes'] + existing_data['pk_bytes']
            await send_frame(writer, peer_info)

            # Envia o novo cliente para cada peer existente
            new_client_info = client_id_bytes + pk_c_bytes
            await send_frame(existing_data['writer'], new_client_info)

        # 2. Registrar o novo cliente na tabela sessions
        sessions[client_id_str] = {
            'writer': writer,
            'public_key': pk_c,
            'client_id_bytes': client_id_bytes,
            'pk_bytes': pk_c_bytes,
            'seq_send': 0,
            'seq_recv': -1,
            'salt': salt_srv
        }

    return client_id_str, client_id_bytes, pk_c_bytes

async def main():
    """Função principal do servidor responsável por inicializar o listener TCP."""

    server = await asyncio.start_server(handle_client, '127.0.0.1', 8888)
    print("Servidor iniciado em 127.0.0.1:8888")

    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
