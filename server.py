import asyncio
from protocol.framing import send_frame, recv_frame

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Função assíncrona executada para cada cliente.
    Realiza o eco das mensagens recebidas de volta para o cliente."""
    
    print(f"Nova conexão de {writer.get_extra_info('peername')}")
    
    try:
        while True:
            # Recebe o frame do cliente utilizando o leitor de stream
            payload = await recv_frame(reader)
            print(f"Recebido payload de {len(payload)} bytes")
            # Devolve o mesmo payload recebido para o cliente (eco)
            await send_frame(writer, payload)
    except asyncio.IncompleteReadError:
        print("Conexão fechada pelo cliente.")
    except ValueError as e: # Payloads que excedem o limite
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