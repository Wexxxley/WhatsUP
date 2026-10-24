import asyncio
import os
from protocol.framing import send_frame, recv_frame
from protocol.ids import generate_client_id, format_client_id
from protocol.keys import generate_key_pair, serialize_public_key

async def main():
    
    client_id = generate_client_id()
    
    # Geração das chaves
    sk, pk = generate_key_pair()
    pk_bytes = serialize_public_key(pk)

    (reader, writer) = await asyncio.open_connection('127.0.0.1', 8888)

    # Frame de registro: client_id (16 bytes) + pk (32 bytes) = 48 bytes
    registration_frame = client_id + pk_bytes
    await send_frame(writer, registration_frame)
    print(f"Enviado ID de registro: {format_client_id(client_id)}")

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

    writer.close()
    await writer.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())

