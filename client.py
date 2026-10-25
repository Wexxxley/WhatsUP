import asyncio
import os
from protocol.framing import send_frame, recv_frame
from protocol.ids import generate_client_id, format_client_id
from protocol.keys import generate_key_pair, serialize_public_key
from protocol.handshake import verify_server_handshake_response

async def main():
    
    # Geração do ID do cliente
    client_id = generate_client_id()
    
    # Geração das chaves pública e privada do cliente
    sk, pk = generate_key_pair()
    pk_bytes = serialize_public_key(pk)

    (reader, writer) = await asyncio.open_connection('127.0.0.1', 8888)

    # Frame de registro: client_id (16 bytes) + pk (32 bytes) = 48 bytes
    registration_frame = client_id + pk_bytes
    await send_frame(writer, registration_frame)
    print(f"Enviado ID de registro: {format_client_id(client_id)}")

    # Receber e verificar resposta do handshake do servidor
    try:
        handshake_response = await recv_frame(reader)
        salt_srv = verify_server_handshake_response(
            handshake_response,
            "certs/server.crt",
            pk_bytes,
            client_id
        )
        print(f"Handshake verificado com sucesso! Salt recebido (hex): {salt_srv.hex()}")
    except Exception as e:
        print(f"ERRO DE HANDSHAKE / AUTENTICAÇÃO DO SERVIDOR: {e}")
        writer.close()
        await writer.wait_closed()
        return

    await tests(reader, writer)

    writer.close()
    await writer.wait_closed()

async def tests(reader, writer):
    # 1. Teste normal
    test_payload = b'ola, este e um teste de framing'
    await send_frame(writer, test_payload)
    print(f"Enviado: {test_payload}")
    response = await recv_frame(reader)
    print(f"Recebido do servidor: {response}")

    # 2. Teste de estresse (4000 bytes)
    stress_payload = os.urandom(4000)
    await send_frame(writer, stress_payload)
    print(f"Enviado payload de {len(stress_payload)} bytes.")
    response = await recv_frame(reader)
    assert response == stress_payload
    print("Payload de 4000 bytes recebido corretamente.")

    # 3. Teste de erro (limite excedido)
    try:
        large_payload = os.urandom(5000)
        await send_frame(writer, large_payload)
        print("Erro: deveria ter falhado ao enviar payload grande")
    except ValueError as e:
        print(f"Sucesso: Erro capturado ao enviar payload grande: {e}")

if __name__ == "__main__":
    asyncio.run(main())
