import asyncio
import secrets
from typing import TypedDict
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_types
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from protocol.framing import send_frame, recv_frame
from protocol.ids import format_client_id
from protocol.keys import deserialize_public_key
from protocol.handshake import (
    create_server_handshake_response
)
from tools.generate_certificate import load_or_generate_server_credentials
from protocol.spec import (
    MIN_E2E_FRAME_SIZE,
    REGISTRATION_FRAME_SIZE,
    CLIENT_ID_SIZE,
    X25519_KEY_SIZE,
    NONCE_SIZE,
)

class SessionData(TypedDict):
    writer: asyncio.StreamWriter
    public_key: X25519PublicKey
    client_id_bytes: bytes
    pk_bytes: bytes
    seq_send: int
    seq_recv: int
    salt: bytes

sessions_lock = asyncio.Lock() # serve para garantir a concorrência segura (thread-safe) e fila de espera
sessions: dict[str, SessionData] = {} # id do cliente -> SessionData

SERVER_PRIV_KEY: rsa_types.RSAPrivateKey | None = None
SERVER_CERT_BYTES: bytes | None = None
SERVER_SALT: bytes | None = None

# ---------------------------------------------------------------------------------

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Função assíncrona executada para cada cliente (isolada por task)."""

    peername = writer.get_extra_info('peername') # tupla do tipo ('127.0.0.1', 42176)
    
    # Declarando antes pq são necessárias fora do try
    client_id_str = None
    client_id_bytes = None

    try:
        # Frame inicial de registro do cliente
        (client_id_str, client_id_bytes, pk_c_bytes) = await registration(reader, writer)

        while True:
            # Recebe o frame do cliente utilizando o leitor de stream
            payload = await recv_frame(reader)

            # Roteamento E2E: se for frame E2E (>= MIN_E2E_FRAME_SIZE), encaminhar para o alvo_id
            if len(payload) >= MIN_E2E_FRAME_SIZE:
                recipient_id_bytes = payload[NONCE_SIZE + CLIENT_ID_SIZE : NONCE_SIZE + 2 * CLIENT_ID_SIZE]
                recipient_id_str = format_client_id(recipient_id_bytes)

                async with sessions_lock:
                    if recipient_id_str in sessions:
                        recipient_writer = sessions[recipient_id_str]['writer']
                        await send_frame(recipient_writer, payload)
                        print(f"[Relay] Frame E2E encaminhado de {client_id_str} para {recipient_id_str} ({len(payload)} bytes)")
                    else:
                        print(f"[Relay] Destinatário {recipient_id_str} não encontrado.")

    except asyncio.IncompleteReadError:
        print(f"Conexão fechada pelo cliente {client_id_str or peername}.")
    except Exception as e:
        print(f"Erro de protocolo / exceção na sessão de {client_id_str or peername}: {e}")
    finally:
        if client_id_str and client_id_bytes:
            async with sessions_lock:
                current_session = sessions.get(client_id_str)
                if current_session is not None and current_session["writer"] is writer:
                    sessions.pop(client_id_str, None)

                    # Notificar pares restantes sobre a saída deste cliente.
                    leave_frame = client_id_bytes + b"\x00" * X25519_KEY_SIZE
                    for other_data in sessions.values():
                        try:
                            await send_frame(other_data['writer'], leave_frame)
                        except (ConnectionError, asyncio.IncompleteReadError):
                            pass

                    print(
                        f"Cliente {client_id_str} removido das sessões e peers notificados."
                    )

        # Garante o fechamento seguro dos recursos de rede ao finalizar a sessão
        writer.close()
        await writer.wait_closed()

async def registration(reader, writer):
    """Função responsável por registrar o cliente, executar o handshake e armazenar sessão."""
    if SERVER_PRIV_KEY is None or SERVER_CERT_BYTES is None:
        raise RuntimeError("Credenciais do servidor não foram carregadas")

    # client_id (16B) + pk (32B)
    registration_frame = await recv_frame(reader)
    if len(registration_frame) != REGISTRATION_FRAME_SIZE:
        raise ValueError("Frame de registro inválido")

    client_id_bytes = registration_frame[:CLIENT_ID_SIZE]
    pk_c_bytes = registration_frame[CLIENT_ID_SIZE:]

    client_id_str = format_client_id(client_id_bytes)
    pk_c = deserialize_public_key(pk_c_bytes)

    # Executar handshake: assinar pk_S || pk_C || client_id || salt_srv
    if SERVER_SALT is None:
        raise RuntimeError("Salt do servidor não foi carregado")
    (handshake_response, salt_srv) = create_server_handshake_response(
        SERVER_PRIV_KEY,
        SERVER_CERT_BYTES,
        pk_c_bytes,
        client_id_bytes,
        SERVER_SALT,
    )

    await send_frame(writer, handshake_response)
    print(f"Handshake realizado com sucesso para o cliente {client_id_str} (salt gerado)")

    replaced_writer = None
    async with sessions_lock:
        # Uma reconexão com o mesmo ID deve substituir a sessão anterior sem
        # permitir que o encerramento tardio da conexão antiga remova a nova.
        previous_session = sessions.pop(client_id_str, None)
        if previous_session is not None:
            replaced_writer = previous_session["writer"]

        # Enviar contagem de clientes online para que o cliente possa esperar x respostas
        num_peers = len(sessions)
        await send_frame(writer, num_peers.to_bytes(4, 'big'))

        for existing_id_str, existing_data in sessions.items():
            # Envia peer para o novo cliente
            peer_info = existing_data['client_id_bytes'] + existing_data['pk_bytes']
            await send_frame(writer, peer_info)

            # Envia o novo cliente para cada peer
            new_client_info = client_id_bytes + pk_c_bytes
            await send_frame(existing_data['writer'], new_client_info)

        # Registrar o novo cliente na tabela sessions
        sessions[client_id_str] = {
            'writer': writer,
            'public_key': pk_c,
            'client_id_bytes': client_id_bytes,
            'pk_bytes': pk_c_bytes,
            'seq_send': 0, # Seq da proxima msg enviada ao cliente
            'seq_recv': -1, # Seq da ultima msg recebida do cliente
            'salt': salt_srv
        }

    if replaced_writer is not None:
        replaced_writer.close()
        await replaced_writer.wait_closed()

    return client_id_str, client_id_bytes, pk_c_bytes

async def main():
    """Função principal do servidor responsável por inicializar o listener TCP."""
    global SERVER_PRIV_KEY, SERVER_CERT_BYTES, SERVER_SALT

    # Reutiliza a credencial pinada; gera-a somente no primeiro startup.
    SERVER_PRIV_KEY, SERVER_CERT_BYTES = load_or_generate_server_credentials()
    SERVER_SALT = secrets.token_bytes(16)

    # Inicializa o servidor, passagem de handle_client como callback para cada nova conexão
    server = await asyncio.start_server(handle_client, '127.0.0.1', 8888)
    print("Servidor iniciado em 127.0.0.1:8888")

    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
