import asyncio
import uuid
from typing import TypedDict
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_types
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from protocol.framing import send_frame, recv_frame
from protocol.keys import deserialize_public_key
from protocol.handshake import (
    create_server_handshake_response
)
from protocol.admin import (
    ADMIN_JOIN,
    ADMIN_LEAVE,
    create_admin_frame,
)
from tools.generate_certificate import generate_server_credentials
from protocol.constants import (
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

# ---------------------------------------------------------------------------------

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Atende uma conexão: registro, relay E2E e limpeza da sessão."""

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
                recipient_id_str = str(uuid.UUID(bytes=recipient_id_bytes))

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

                    # Notificar cada peer com um anúncio assinado e endereçado.
                    for other_data in sessions.values():
                        try:
                            leave_frame = create_admin_frame(
                                SERVER_PRIV_KEY,
                                ADMIN_LEAVE,
                                _next_admin_seq(other_data),
                                client_id_bytes,
                                other_data["client_id_bytes"],
                                b"\x00" * X25519_KEY_SIZE,
                                current_session["salt"],
                            )
                            await send_frame(other_data['writer'], leave_frame)
                        except (ConnectionError, asyncio.IncompleteReadError):
                            pass

                    print(
                        f"Cliente {client_id_str} removido das sessões e peers notificados."
                    )

        # Garante o fechamento seguro dos recursos de rede ao finalizar a sessão
        writer.close()
        await writer.wait_closed()

# Fase 2: registro do cliente, handshake e anúncio de peers
async def registration(reader, writer):
    """Executa as Fases 2 e 4: handshake, anúncio de peers e registro da sessão."""
    if SERVER_PRIV_KEY is None or SERVER_CERT_BYTES is None:
        raise RuntimeError("Credenciais do servidor não foram carregadas")

    # client_id (16B) + pk (32B)
    registration_frame = await recv_frame(reader)
    if len(registration_frame) != REGISTRATION_FRAME_SIZE:
        raise ValueError("Frame de registro inválido")

    client_id_bytes = registration_frame[:CLIENT_ID_SIZE]
    pk_c_bytes = registration_frame[CLIENT_ID_SIZE:]

    client_id_str = str(uuid.UUID(bytes=client_id_bytes))
    pk_c = deserialize_public_key(pk_c_bytes)

    # O handshake gera um salt novo para esta conexão.
    (handshake_response, salt_srv) = create_server_handshake_response(
        SERVER_PRIV_KEY,
        SERVER_CERT_BYTES,
        pk_c_bytes,
        client_id_bytes,
    )

    async with sessions_lock:
        # O client_id identifica uma sessão única; não substituímos uma sessão ativa.
        if client_id_str in sessions:
            raise ValueError(f"client_id já conectado: {client_id_str}")

        await send_frame(writer, handshake_response)
        print(f"Handshake realizado com sucesso para o cliente {client_id_str}")

        # Enviar contagem de clientes online para que o cliente possa esperar x respostas
        num_peers = len(sessions)
        await send_frame(writer, num_peers.to_bytes(4, 'big'))

        new_session: SessionData = {
            'writer': writer,
            'public_key': pk_c,
            'client_id_bytes': client_id_bytes,
            'pk_bytes': pk_c_bytes,
            'seq_send': 0,
            'seq_recv': -1,
            'salt': salt_srv,
        }

        for existing_data in sessions.values():
            # Enviar informações de cada peer existente para o novo cliente
            peer_info = create_admin_frame(
                server_private_key=SERVER_PRIV_KEY,
                announcement_type=ADMIN_JOIN,
                seq_admin=_next_admin_seq(new_session),
                announced_id=existing_data['client_id_bytes'],
                recipient_id=client_id_bytes,
                public_key=existing_data['pk_bytes'],
                salt_srv=salt_srv,
            )
            await send_frame(writer, peer_info)

            # Enviar informações do novo cliente para cada peer existente
            new_client_info = create_admin_frame(
                server_private_key=SERVER_PRIV_KEY,
                announcement_type=ADMIN_JOIN,
                seq_admin=_next_admin_seq(existing_data),
                announced_id=client_id_bytes,
                recipient_id=existing_data['client_id_bytes'],
                public_key=pk_c_bytes,
                salt_srv=salt_srv,
            )
            await send_frame(existing_data['writer'], new_client_info)

        # Registrar o novo cliente na tabela sessions
        sessions[client_id_str] = new_session

    return client_id_str, client_id_bytes, pk_c_bytes

def _next_admin_seq(session: SessionData) -> int:
    seq_admin = session['seq_send']
    session['seq_send'] += 1
    return seq_admin

async def main():
    """Fase 0: cria credenciais e inicia o listener de conexões."""
    global SERVER_PRIV_KEY, SERVER_CERT_BYTES

    # Gera uma nova identidade do servidor a cada inicialização.
    SERVER_PRIV_KEY, SERVER_CERT_BYTES = generate_server_credentials()
    # Inicializa o servidor, passagem de handle_client como callback para cada nova conexão
    server = await asyncio.start_server(handle_client, '127.0.0.1', 8888)
    print("Servidor iniciado em 127.0.0.1:8888")

    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
