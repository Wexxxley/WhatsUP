import asyncio
from protocol.framing import send_frame, recv_frame

async def main():
    """Gerencia a execução do cliente"""
    # Estabelece uma conexão TCP assíncrona com o servidor no endereço local e porta 8888
    # Reader: canal de recebimento de dados, Writer: canal de envio de dados
    (reader, writer) = await asyncio.open_connection('127.0.0.1', 8888)
    print("Conectado ao servidor.")
    
    test_payload = "ola, este e um teste de framing".encode('utf-8')
    
    await send_frame(writer, test_payload)
    
    response = await recv_frame(reader)
    print(f"Recebido do servidor: {response.decode('utf-8')}")
    
    # Fecha o canal de escrita e aguarda o encerramento completo da conexão
    writer.close()
    await writer.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())