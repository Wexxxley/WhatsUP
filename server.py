import asyncio
from typing import TypedDict
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from protocol.framing import send_frame, recv_frame
from protocol.ids import format_client_id
from protocol.keys import deserialize_public_key

class SessionData(TypedDict):
    writer: asyncio.StreamWriter
    public_key: X25519PublicKey
    seq_send: int
    seq_recv: int
    salt: bytes

sessions: dict[str, SessionData] = {}

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Função assíncrona executada para cada cliente."""

    peername = writer.get_extra_info('peername')
    print(f"Nova conexão de {peername}")

    try:
        # Primeiro frame -> registro: client_id (16B) + pk (32B) = 48B
        registration_frame = await recv_frame(reader)
        if len(registration_frame) != 48:
            raise ValueError("Frame de registro inválido")

        client_id_bytes = registration_frame[:16]
        pk_c_bytes = registration_frame[16:]

        client_id_str = format_client_id(client_id_bytes)
        pk_c = deserialize_public_key(pk_c_bytes)

        sessions[client_id_str] = {
            'writer': writer,
            'public_key': pk_c,
            'seq_send': 0,  # número sequencial da próxima mensagem que este cliente vai enviar.
            'seq_recv': -1, # número sequencial da última mensagem válida que este cliente recebeu.
            'salt': b''
        }

        while True:
            # Recebe o frame do cliente utilizando o leitor de stream
            payload = await recv_frame(reader)
            print(f"Recebido payload de {len(payload)} bytes de {client_id_str}")
            # Devolve o mesmo payload recebido para o cliente (eco)
            await send_frame(writer, payload)

    except asyncio.IncompleteReadError:
        print("Conexão fechada pelo cliente.")
    except ValueError as e:
        print(f"Erro de protocolo: {e}")
    finally:
        # Garante o fechamento seguro dos recursos de rede ao finalizar a sessão
        writer.close()
        await writer.wait_closed()

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