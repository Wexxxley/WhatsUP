import asyncio
from protocol.framing import send_frame, recv_frame
from protocol.ids import format_client_id

# Dicionário para armazenar sessões ativas, mapeando client_id para o writer correspondente
sessions: dict[str, asyncio.StreamWriter] = {}

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Função assíncrona executada para cada cliente."""

    peername = writer.get_extra_info('peername')
    print(f"Nova conexão de {peername}")

    try:
        # Primeiro frame deve ser o registro do client_id
        client_id_bytes = await recv_frame(reader)
        if len(client_id_bytes) != 16:
            raise ValueError("ID de cliente inválido")

        client_id_str = format_client_id(client_id_bytes)
        sessions[client_id_str] = writer
        print(f"Cliente {client_id_str} registrado.")

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