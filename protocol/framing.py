import asyncio

MAX_FRAME_SIZE = 4200

async def send_frame(writer: asyncio.StreamWriter, payload: bytes):
    """ Empacota e envia um payload através do canal de escrita (writer).
    Prefixo-4B + payload-nB"""
    
    if len(payload) > MAX_FRAME_SIZE:
        raise ValueError("Payload excedeu o limite máximo")
    length = len(payload)
    # Escreve no canal de escrita
    writer.write(length.to_bytes(4, 'big') + payload)
    # Espera o buffer ser esvaziado para garantir que os dados foram enviados
    await writer.drain() 

async def recv_frame(reader: asyncio.StreamReader) -> bytes:
    """ Lê um frame completo a partir do canal de leitura (reader). """
    
    # Lê exatamente 4 bytes para obter o cabeçalho de tamanho
    length_bytes = await reader.readexactly(4)
    # Converte os 4 bytes big-endian de volta para um valor inteiro
    length = int.from_bytes(length_bytes, 'big')
    if length > MAX_FRAME_SIZE:
        raise ValueError("Frame recebido excede o limite máximo")
    # Lê exatamente o número de bytes correspondente ao payload do frame
    return await reader.readexactly(length)

# 1000 em hexadecimal -> 0x03 0xE8 (2 bytes)
# Se formos transformar esse número em 4 bytes Big-Endian: 00 00 03 E8
