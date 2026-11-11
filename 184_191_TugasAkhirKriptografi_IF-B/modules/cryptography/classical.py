"""
==============================================================================
MODUL: KRIPTOGRAFI KLASIK - VIGENÈRE CIPHER (MANUAL NATIVE)
==============================================================================
Deskripsi:
Modul ini mengimplementasikan algoritma kriptografi klasik Vigenère Cipher
secara manual murni (native Python) tanpa menggunakan pustaka pihak ketiga.

Konsep & Rumus Matematis:
Vigenère Cipher adalah cipher substitusi polialfabetik yang menggunakan kata kunci
untuk menentukan pergeseran karakter berdasarkan matriks Tabula Recta.

1. Mode Alfabet Tradisional (Modulo 26):
   - Enkripsi: C_i = (P_i + K_(i mod m)) mod 26
   - Dekripsi: P_i = (C_i - K_(i mod m) + 26) mod 26
   Di mana:
     P_i = Nilai numerik karakter plaintext (A=0, ..., Z=25)
     K_i = Nilai numerik karakter kunci
     m   = Panjang kunci

2. Mode Extended Byte Vigenère (Modulo 256):
   - Mengenkripsi seluruh rentang byte UTF-8 (termasuk spasi, angka, simbol, baris baru).
   - Enkripsi: C_i = (P_i + K_(i mod m)) mod 256
   - Dekripsi: P_i = (C_i - K_(i mod m) + 256) mod 256
   Sangat cocok untuk pesan chat modern agar format pesan tidak rusak.
==============================================================================
"""

import base64


def _clean_key(key: str) -> str:
    """Membersihkan dan memvalidasi kunci Vigenère."""
    if not isinstance(key, str) or not key.strip():
        raise ValueError("Kunci Vigenère tidak boleh kosong dan harus berupa teks.")
    return key


def vigenere_encrypt_alphabetic(plaintext: str, key: str) -> str:
    """
    Enkripsi Vigenère Klasik Tradisional (A-Z, a-z) Modulo 26.
    Mempertahankan huruf besar/kecil. Karakter non-alfabet (angka, spasi) tidak diubah.
    
    Contoh:
        plaintext = "ATTACK AT DAWN", key = "LEMON" -> "LXFOPV EF RNHR"
    """
    key = _clean_key(key)
    key_letters = [c.upper() for c in key if c.isalpha()]
    if not key_letters:
        raise ValueError("Kunci alfabetik minimal harus memiliki 1 karakter huruf (A-Z).")
        
    result = []
    key_len = len(key_letters)
    key_index = 0
    
    for char in plaintext:
        if char.isalpha():
            is_upper = char.isupper()
            base = ord('A') if is_upper else ord('a')
            
            p_val = ord(char) - base
            k_val = ord(key_letters[key_index % key_len]) - ord('A')
            
            # Rumus Enkripsi: C = (P + K) mod 26
            c_val = (p_val + k_val) % 26
            result.append(chr(c_val + base))
            
            key_index += 1
        else:
            # Karakter selain huruf dipertahankan
            result.append(char)
            
    return "".join(result)


def vigenere_decrypt_alphabetic(ciphertext: str, key: str) -> str:
    """
    Dekripsi Vigenère Klasik Tradisional Modulo 26.
    """
    key = _clean_key(key)
    key_letters = [c.upper() for c in key if c.isalpha()]
    if not key_letters:
        raise ValueError("Kunci alfabetik minimal harus memiliki 1 karakter huruf (A-Z).")
        
    result = []
    key_len = len(key_letters)
    key_index = 0
    
    for char in ciphertext:
        if char.isalpha():
            is_upper = char.isupper()
            base = ord('A') if is_upper else ord('a')
            
            c_val = ord(char) - base
            k_val = ord(key_letters[key_index % key_len]) - ord('A')
            
            # Rumus Dekripsi: P = (C - K + 26) mod 26
            p_val = (c_val - k_val + 26) % 26
            result.append(chr(p_val + base))
            
            key_index += 1
        else:
            result.append(char)
            
    return "".join(result)


def vigenere_encrypt_bytes(data: bytes, key: str) -> bytes:
    """
    Extended Vigenère Cipher Modulo 256 pada level byte biner.
    Mendukung seluruh karakter teks UTF-8 termasuk emoji, simbol, dan spasi.
    
    Rumus: C_i = (P_i + K_(i mod m)) mod 256
    """
    key = _clean_key(key)
    key_bytes = key.encode("utf-8")
    key_len = len(key_bytes)
    
    encrypted_bytes = bytearray(len(data))
    for i, b in enumerate(data):
        k_b = key_bytes[i % key_len]
        encrypted_bytes[i] = (b + k_b) % 256
        
    return bytes(encrypted_bytes)


def vigenere_decrypt_bytes(ciphertext_bytes: bytes, key: str) -> bytes:
    """
    Dekripsi Extended Vigenère Cipher Modulo 256 pada level byte biner.
    
    Rumus: P_i = (C_i - K_(i mod m) + 256) mod 256
    """
    key = _clean_key(key)
    key_bytes = key.encode("utf-8")
    key_len = len(key_bytes)
    
    decrypted_bytes = bytearray(len(ciphertext_bytes))
    for i, b in enumerate(ciphertext_bytes):
        k_b = key_bytes[i % key_len]
        decrypted_bytes[i] = (b - k_b + 256) % 256
        
    return bytes(decrypted_bytes)


def vigenere_encrypt(plaintext: str, key: str, mode: str = "extended") -> str:
    """
    Wrapper fungsi enkripsi Vigenère tingkat tinggi.
    
    Args:
        plaintext (str): Teks pesan asli.
        key (str): Kunci rahasia Vigenère.
        mode (str): 'extended' (default, output base64) atau 'alphabetic' (output teks A-Z).
        
    Returns:
        str: Hasil ciphertext.
    """
    if mode == "alphabetic":
        return vigenere_encrypt_alphabetic(plaintext, key)
    elif mode == "extended":
        enc_bytes = vigenere_encrypt_bytes(plaintext.encode("utf-8"), key)
        return base64.b64encode(enc_bytes).decode("ascii")
    else:
        raise ValueError(f"Mode Vigenère '{mode}' tidak dikenal. Pilih 'extended' atau 'alphabetic'.")


def vigenere_decrypt(ciphertext: str, key: str, mode: str = "extended") -> str:
    """
    Wrapper fungsi dekripsi Vigenère tingkat tinggi.
    
    Args:
        ciphertext (str): Teks pesan terenkripsi.
        key (str): Kunci rahasia Vigenère.
        mode (str): 'extended' atau 'alphabetic'.
        
    Returns:
        str: Pesan plaintext asli yang berhasil didekripsi.
    """
    if mode == "alphabetic":
        return vigenere_decrypt_alphabetic(ciphertext, key)
    elif mode == "extended":
        try:
            raw_bytes = base64.b64decode(ciphertext.encode("ascii"))
            dec_bytes = vigenere_decrypt_bytes(raw_bytes, key)
            # Gunakan errors='replace' agar jika kunci Vigenere salah, output menjadi
            # karakter acak (gibberish/mojibake) sesuai karakteristik cipher klasik, bukan crash.
            return dec_bytes.decode("utf-8", errors="replace")
        except Exception as e:
            raise ValueError(f"Dekripsi Vigenère gagal (format ciphertext tidak valid): {str(e)}")
    else:
        raise ValueError(f"Mode Vigenère '{mode}' tidak dikenal. Pilih 'extended' atau 'alphabetic'.")
