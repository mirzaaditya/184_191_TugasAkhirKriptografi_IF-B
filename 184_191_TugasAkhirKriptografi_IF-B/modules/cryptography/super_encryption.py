"""
==============================================================================
MODUL: SUPER ENKRIPSI PESAN TEKS (VIGENÈRE CIPHER + AES-256-GCM)
==============================================================================
Deskripsi:
Modul ini mengimplementasikan konsep Super Enkripsi (Hybrid Cascaded Cipher)
dengan menggabungkan cipher klasik (Vigenère) dan cipher modern (AES-256-GCM).

Alur Super Enkripsi (Enkripsi Bertingkat):
1. Input: Pesan Plaintext Teks Asli.
2. Lapisan 1 (Klasik): Teks dienkripsi dengan Vigenère Cipher menghasilkan
   Intermediate Ciphertext.
3. Lapisan 2 (Modern): Intermediate Ciphertext dienkripsi kembali dengan
   AES-256-GCM menghasilkan Final Ciphertext (Nonce + Ciphertext + Tag).

Alur Super Dekripsi:
1. Input: Final Ciphertext.
2. Lapisan 1: Dekripsi AES-256-GCM dan verifikasi authentication tag (AEAD).
   Jika kunci salah atau ciphertext dimanipulasi, proses langsung dihentikan.
3. Lapisan 2: Dekripsi Vigenère Cipher pada intermediate ciphertext.
4. Output: Plaintext Asli.

Mengapa Super Enkripsi?
- Memenuhi prinsip "Defense-in-Depth": Kerusakan pada salah satu algoritma
  tidak langsung membocorkan kerahasiaan teks.
- Memberikan demonstrasi evolusi kriptografi (Klasik -> Modern) untuk
  keperluan akademis Tugas Akhir.
==============================================================================
"""

import time
from modules.cryptography.classical import (
    vigenere_encrypt,
    vigenere_decrypt,
    vigenere_encrypt_alphabetic,
    vigenere_decrypt_alphabetic
)
from modules.cryptography.modern import (
    aes_encrypt,
    aes_decrypt_text
)


def super_encrypt(
    plaintext: str,
    vigenere_key: str,
    aes_key: str | bytes,
    mode: str = "extended"
) -> dict:
    """
    Menjalankan proses Super Enkripsi (Vigenère -> AES-256-GCM).
    
    Args:
        plaintext (str): Pesan teks biasa.
        vigenere_key (str): Kunci untuk algoritma Vigenère.
        aes_key (str | bytes): Kunci / passphrase untuk AES-256.
        mode (str): 'extended' (full Unicode/byte) atau 'alphabetic' (tradisional A-Z).
        
    Returns:
        dict: Hasil enkripsi lengkap beserta tahapan intermediate untuk visualisasi demo.
    """
    if not plaintext:
        raise ValueError("Pesan plaintext tidak boleh kosong.")
        
    start_time = time.perf_counter()
    
    # TAHAP 1: Enkripsi Klasik (Vigenère)
    if mode == "alphabetic":
        intermediate_text = vigenere_encrypt_alphabetic(plaintext, vigenere_key)
    else:
        intermediate_text = vigenere_encrypt(plaintext, vigenere_key, mode="extended")
        
    # TAHAP 2: Enkripsi Modern (AES-256-GCM)
    final_ciphertext_b64 = aes_encrypt(
        plaintext=intermediate_text,
        key=aes_key,
        associated_data=b"SUPER_ENCRYPTED_MESSAGE_V1"
    )
    
    elapsed_ms = (time.perf_counter() - start_time) * 1000
    
    return {
        "final_ciphertext": final_ciphertext_b64,
        "intermediate_vigenere": intermediate_text,
        "original_length": len(plaintext),
        "ciphertext_length": len(final_ciphertext_b64),
        "encryption_time_ms": round(elapsed_ms, 3),
        "mode": mode,
        "algorithms": "Vigenere Cipher + AES-256-GCM"
    }


def super_decrypt(
    final_ciphertext_b64: str,
    vigenere_key: str,
    aes_key: str | bytes,
    mode: str = "extended"
) -> dict:
    """
    Menjalankan proses Super Dekripsi (AES-256-GCM -> Vigenère).
    
    Args:
        final_ciphertext_b64 (str): Ciphertext gabungan Base64.
        vigenere_key (str): Kunci untuk algoritma Vigenère.
        aes_key (str | bytes): Kunci / passphrase untuk AES-256.
        mode (str): 'extended' atau 'alphabetic'.
        
    Returns:
        dict: Hasil dekripsi lengkap (plaintext asli dan intermediate text).
        
    Raises:
        ValueError: Jika kunci salah atau data telah dimodifikasi.
    """
    if not final_ciphertext_b64:
        raise ValueError("Ciphertext tidak boleh kosong.")
        
    start_time = time.perf_counter()
    
    # TAHAP 1: Dekripsi Modern (AES-256-GCM) + Validasi Tag Integritas
    intermediate_text = aes_decrypt_text(
        ciphertext_b64=final_ciphertext_b64,
        key=aes_key,
        associated_data=b"SUPER_ENCRYPTED_MESSAGE_V1"
    )
    
    # TAHAP 2: Dekripsi Klasik (Vigenère)
    if mode == "alphabetic":
        recovered_plaintext = vigenere_decrypt_alphabetic(intermediate_text, vigenere_key)
    else:
        recovered_plaintext = vigenere_decrypt(intermediate_text, vigenere_key, mode="extended")
        
    elapsed_ms = (time.perf_counter() - start_time) * 1000
    
    return {
        "plaintext": recovered_plaintext,
        "intermediate_vigenere": intermediate_text,
        "decryption_time_ms": round(elapsed_ms, 3),
        "mode": mode
    }

