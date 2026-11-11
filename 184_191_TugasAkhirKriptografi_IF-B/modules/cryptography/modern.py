"""
==============================================================================
MODUL: KRIPTOGRAFI MODERN - AES-256-GCM (AUTHENTICATED ENCRYPTION)
==============================================================================
Deskripsi:
Modul ini mengimplementasikan algoritma simetris modern Advanced Encryption
Standard (AES) dengan panjang kunci 256-bit dalam mode GCM (Galois/Counter Mode).

Mengapa AES-256-GCM?
1. Kerahasiaan (Confidentiality): Menjamin data tidak dapat dibaca pihak ketiga.
2. Integritas & Otentikasi (AEAD): Menghasilkan authentication tag (128-bit)
   yang memvalidasi bahwa ciphertext belum dimanipulasi sama sekali.
3. Kinerja Tinggi: Mode GCM dapat diparalelkan dan sangat efisien.
4. Keamanan Standar Militer/Pemerintah: Standar NIST FIPS 197.
==============================================================================
"""

import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


def derive_aes_key(passphrase_or_key: str | bytes) -> bytes:
    """
    Menghasilkan kunci AES 256-bit (tepat 32 bytes) dari input passphrase atau string.
    Menggunakan SHA-256 sebagai Key Derivation Function deterministik.
    """
    if isinstance(passphrase_or_key, str):
        passphrase_or_key = passphrase_or_key.encode("utf-8")
        
    return hashlib.sha256(passphrase_or_key).digest()


def aes_encrypt(plaintext: str | bytes, key: str | bytes, associated_data: bytes = None) -> str:
    """
    Mengenkripsi data menggunakan AES-256-GCM.
    
    Args:
        plaintext (str | bytes): Data yang akan dienkripsi.
        key (str | bytes): Kunci enkripsi (string atau bytes 32-byte).
        associated_data (bytes, optional): Data otentikasi tambahan (AAD).
        
    Returns:
        str: String Base64 yang berisi gabungan: [Nonce 12-byte] + [Ciphertext + Tag 16-byte].
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
        
    aes_key = derive_aes_key(key)
    aesgcm = AESGCM(aes_key)
    
    # Generate 96-bit (12 bytes) Nonce acak unik per enkripsi
    nonce = os.urandom(12)
    
    # Enkripsi data (AESGCM secara otomatis menyematkan 16-byte auth tag di akhir ciphertext)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
    
    # Gabungkan Nonce + Ciphertext (dengan tag)
    payload = nonce + ciphertext_with_tag
    
    return base64.b64encode(payload).decode("ascii")


def aes_decrypt(ciphertext_b64: str, key: str | bytes, associated_data: bytes = None) -> bytes:
    """
    Mendekripsi data terenkripsi AES-256-GCM dan memverifikasi integritasnya.
    
    Args:
        ciphertext_b64 (str): String Base64 hasil enkripsi (Nonce + Ciphertext + Tag).
        key (str | bytes): Kunci dekripsi.
        associated_data (bytes, optional): Data otentikasi tambahan (harus sama dengan saat enkripsi).
        
    Returns:
        bytes: Data asli (plaintext) hasil dekripsi.
        
    Raises:
        ValueError: Jika format ciphertext rusak, ukuran kurang dari nonce+tag,
                    atau kunci salah / data telah dimanipulasi (InvalidTag).
    """
    try:
        payload = base64.b64decode(ciphertext_b64.encode("ascii"))
    except Exception as e:
        raise ValueError(f"Ciphertext bukan format Base64 yang valid: {str(e)}")
        
    # Nonce (12 bytes) + Tag minimum (16 bytes) = 28 bytes
    if len(payload) < 28:
        raise ValueError("Ciphertext terlalu pendek atau file rusak (kurang dari ukuran nonce + tag).")
        
    nonce = payload[:12]
    ciphertext_with_tag = payload[12:]
    
    aes_key = derive_aes_key(key)
    aesgcm = AESGCM(aes_key)
    
    try:
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
        return decrypted_bytes
    except InvalidTag:
        raise ValueError(
            "DEKRIPSI AES GAGAL (InvalidTag): Kunci salah atau pesan telah dimanipulasi / rusak!"
        )


def aes_decrypt_text(ciphertext_b64: str, key: str | bytes, associated_data: bytes = None) -> str:
    """
    Versi dekripsi pembungkus yang langsung mengembalikan string teks UTF-8.
    """
    decrypted_bytes = aes_decrypt(ciphertext_b64, key, associated_data)
    return decrypted_bytes.decode("utf-8")

