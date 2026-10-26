import asyncio
import os
from typing import TypedDict
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from protocol.framing import send_frame, recv_frame
from protocol.ids import generate_client_id, format_client_id
from protocol.keys import generate_key_pair, serialize_public_key, deserialize_public_key
from protocol.handshake import verify_server_handshake_response
from protocol.crypto import derive_e2e_keys

class PeerData(TypedDict):
    public_key: X25519PublicKey
    key_send: bytes
    key_recv: bytes
    seq_send: int
    seq_recv: int
    IV_base_send: bytes
    IV_base_recv: bytes | None

async def main():
    
    # Geração do ID do cliente
    client_id = generate_client_id()
    client_id_str = format_client_id(client_id)
    print(f"Meu client_id: {client_id_str}")
    
    # Geração das chaves pública e privada do cliente
    sk, pk = generate_key_pair()
    pk_bytes = serialize_public_key(pk)

    peers: dict[str, PeerData] = {}

    (reader, writer) = await asyncio.open_connection('127.0.0.1', 8888)

    # Frame de registro: client_id (16 bytes) + pk (32 bytes) = 48 bytes
    registration_frame = client_id + pk_bytes
    await send_frame(writer, registration_frame)
    print(f"Enviado ID de registro: {client_id_str}")

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

        # Receber número de peers existentes
        num_peers_bytes = await recv_frame(reader)
        num_peers = int.from_bytes(num_peers_bytes, 'big')
        print(f"Recebendo {num_peers} peer(s) inicial(is)...")

        for _ in range(num_peers):
            peer_frame = await recv_frame(reader)
            if len(peer_frame) != 48:
                raise ValueError("Frame de peer inválido")
            peer_client_id_bytes = peer_frame[:16]
            peer_pk_bytes = peer_frame[16:]
            peer_id_str = format_client_id(peer_client_id_bytes)

            key_send, key_recv, iv_base_send = derive_e2e_keys(
                sk, peer_pk_bytes, client_id, peer_client_id_bytes, salt_srv
            )
            peers[peer_id_str] = {
                "public_key": deserialize_public_key(peer_pk_bytes),
                "key_send": key_send,
                "key_recv": key_recv,
                "seq_send": 0,
                "seq_recv": -1,
                "IV_base_send": iv_base_send,
                "IV_base_recv": None
            }
            print(f"Derivadas chaves E2E para peer inicial: {peer_id_str}")

    except Exception as e:
        print(f"ERRO DE HANDSHAKE / DERIVAÇÃO DE CHAVES: {e}")
        writer.close()
        await writer.wait_closed()
        return

    await tests(reader, writer, peers, client_id)

    writer.close()
    await writer.wait_closed()

async def tests(reader, writer, peers: dict[str, PeerData], client_id):
    print(f"Tabela de peers atual ({len(peers)} peers): {list(peers.keys())}")
    
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
