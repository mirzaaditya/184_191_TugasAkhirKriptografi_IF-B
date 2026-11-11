"""
==============================================================================
MODUL BANTUAN STEGANOGRAFI (STEGO COMMON & PRE-ENCRYPTION AES-256-GCM)
==============================================================================
Deskripsi:
Modul ini menyediakan fungsi umum untuk alur kerja steganografi:
1. Pra-enkripsi pesan rahasia menggunakan AES-256-GCM (Authenticated Encryption).
2. Pembentukan payload terstandarisasi: [MAGIC: 4B] + [PANJANG: 4B] + [CIPHERTEXT_AES].
3. Konversi data biner ke representasi bit stream (0 dan 1) untuk penyisipan LSB.
4. Dekonversi bit stream kembali ke byte dan dekripsi AES-256-GCM.
==============================================================================
"""

import os
import struct
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

STEGO_MAGIC_HEADER = b"SMSG"  # 4 Bytes Magic Header
HEADER_SIZE_BYTES = 8         # 4B Magic + 4B Panjang Payload (Big-Endian uint32)


def bytes_to_bits(data: bytes) -> list[int]:
    """
    Mengonversi deretan bytes menjadi daftar bit integer (0 dan 1), MSB ke LSB.
    """
    bits = []
    for b in data:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    return bits


def bits_to_bytes(bits: list[int] | bytes) -> bytes:
    """
    Mengonversi daftar bit integer (0 dan 1) kembali menjadi deretan bytes.
    """
    byte_arr = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte_val = 0
        for bit_idx in range(8):
            byte_val = (byte_val << 1) | int(bits[i + bit_idx])
        byte_arr.append(byte_val)
    return bytes(byte_arr)


def prepare_encrypted_payload(secret_message: str | bytes, aes_key: str | bytes) -> bytes:
    """
    Mengenkripsi pesan rahasia dengan AES-256-GCM dan mengemasnya ke dalam format payload.
    
    Format Payload:
    [MAGIC: 4 Bytes b'SMSG'] + [PANJANG: 4 Bytes uint32] + [NONCE: 12 Bytes] + [CIPHERTEXT + TAG: 16 Bytes]
    """
    if isinstance(secret_message, str):
        secret_bytes = secret_message.encode("utf-8")
    else:
        secret_bytes = secret_message
        
    if not secret_bytes:
        raise ValueError("Pesan rahasia tidak boleh kosong.")
        
    # Turunkan kunci AES 256-bit
    if isinstance(aes_key, str):
        aes_key = aes_key.encode("utf-8")
    key_32b = hashlib.sha256(aes_key).digest()
    
    aesgcm = AESGCM(key_32b)
    nonce = os.urandom(12)  # 96-bit nonce
    
    # Enkripsi dengan associated data untuk integritas header
    ciphertext_with_tag = aesgcm.encrypt(nonce, secret_bytes, b"STEGO_PAYLOAD_V1")
    encrypted_blob = nonce + ciphertext_with_tag
    
    payload_len = len(encrypted_blob)
    header = STEGO_MAGIC_HEADER + struct.pack(">I", payload_len)
    
    return header + encrypted_blob


def decrypt_extracted_payload(raw_extracted_bytes: bytes, aes_key: str | bytes) -> str:
    """
    Memeriksa header steganografi dan mendekripsi ciphertext AES-256-GCM yang diekstraksi.
    
    Raises:
        ValueError: Jika magic header tidak cocok atau dekripsi gagal (kunci salah / file rusak).
    """
    if len(raw_extracted_bytes) < HEADER_SIZE_BYTES:
        raise ValueError("Data yang diekstraksi terlalu pendek untuk memuat header steganografi.")
        
    magic = raw_extracted_bytes[:4]
    if magic != STEGO_MAGIC_HEADER:
        raise ValueError("Media carrier ini tidak memuat pesan rahasia steganografi (Magic Header tidak cocok).")
        
    payload_len = struct.unpack(">I", raw_extracted_bytes[4:8])[0]
    total_required = HEADER_SIZE_BYTES + payload_len
    
    if len(raw_extracted_bytes) < total_required:
        raise ValueError(
            f"Data steganografi terpotong: Membutuhkan {total_required} bytes, hanya tersedia {len(raw_extracted_bytes)} bytes."
        )
        
    encrypted_blob = raw_extracted_bytes[HEADER_SIZE_BYTES:total_required]
    
    if len(encrypted_blob) < 28:  # 12B Nonce + 16B Tag
        raise ValueError("Ukuran payload terenkripsi tidak valid.")
        
    nonce = encrypted_blob[:12]
    ciphertext_with_tag = encrypted_blob[12:]
    
    if isinstance(aes_key, str):
        aes_key = aes_key.encode("utf-8")
    key_32b = hashlib.sha256(aes_key).digest()
    
    aesgcm = AESGCM(key_32b)
    try:
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, b"STEGO_PAYLOAD_V1")
        return decrypted_bytes.decode("utf-8")
    except InvalidTag:
        raise ValueError("DEKRIPSI STEGANOGRAFI GAGAL: Kunci AES salah atau media pembawa telah dimodifikasi!")
    except Exception as e:
        raise ValueError(f"Gagal mendekripsi payload steganografi: {str(e)}")
