"""
==============================================================================
MODUL: HASHER (PASSWORD SECURITY DENGAN PBKDF2-HMAC-SHA256)
==============================================================================
Deskripsi:
Modul ini mengimplementasikan pengamanan kata sandi menggunakan algoritma
standar industri PBKDF2 (Password-Based Key Derivation Function 2) dengan
fungsi pseudo-random HMAC-SHA256 dan cryptographic salt acak.

Mengapa PBKDF2 + Salt?
1. Salt Acak: Mencegah Rainbow Table Attack dan menjamin dua pengguna
   dengan password yang sama menghasilkan nilai hash yang berbeda.
2. Iterasi Tinggi (100.000 putaran): Memperlambat komputasi brute-force
   dan dictionary attack (membuat penyerang membutuhkan resource CPU/GPU
   yang masif).
3. Constant-Time Comparison: Mencegah serangan timing side-channel saat
   membandingkan hash.
==============================================================================
"""

import os
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidKey
from config.settings import PBKDF2_ITERATIONS, PBKDF2_SALT_BYTES, PBKDF2_KEY_LENGTH


def generate_salt(length: int = PBKDF2_SALT_BYTES) -> bytes:
    """
    Menghasilkan cryptographic salt acak menggunakan os.urandom (CSPRNG).
    
    Args:
        length (int): Panjang byte salt (default 16 bytes = 128 bit).
        
    Returns:
        bytes: Byte salt acak.
    """
    return os.urandom(length)


def hash_password(password: str, salt: bytes = None) -> tuple[str, str]:
    """
    Melakukan hashing pada password menggunakan PBKDF2-HMAC-SHA256.
    
    Args:
        password (str): Password teks biasa yang dimasukkan pengguna.
        salt (bytes, optional): Salt kustom jika ingin merekonstruksi hash.
                               Jika None, salt baru akan dibuat otomatis.
                               
    Returns:
        tuple[str, str]: Pasangan (hash_hex, salt_hex) dalam bentuk string heksadesimal.
        
    Raises:
        ValueError: Jika password kosong atau bukan string.
    """
    if not isinstance(password, str) or not password:
        raise ValueError("Password tidak boleh kosong dan harus berupa teks.")
        
    if salt is None:
        salt = generate_salt()
        
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=PBKDF2_KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS
    )
    
    derived_key = kdf.derive(password.encode("utf-8"))
    
    return derived_key.hex(), salt.hex()


def verify_password(password: str, salt_hex: str, expected_hash_hex: str) -> bool:
    """
    Memverifikasi apakah password yang dimasukkan cocok dengan hash yang tersimpan.
    Menggunakan secrets.compare_digest untuk mencegah Timing Side-Channel Attack.
    
    Args:
        password (str): Password yang dimasukkan untuk verifikasi.
        salt_hex (str): Salt tersimpan dalam format heksadesimal.
        expected_hash_hex (str): Nilai hash tersimpan dalam format heksadesimal.
        
    Returns:
        bool: True jika password valid, False jika salah.
    """
    if not password or not salt_hex or not expected_hash_hex:
        return False
        
    try:
        salt_bytes = bytes.fromhex(salt_hex)
        expected_hash_bytes = bytes.fromhex(expected_hash_hex)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=PBKDF2_KEY_LENGTH,
            salt=salt_bytes,
            iterations=PBKDF2_ITERATIONS
        )
        
        # kdf.verify() melempar InvalidKey jika tidak cocok, atau return None jika cocok
        kdf.verify(password.encode("utf-8"), expected_hash_bytes)
        return True
    except (InvalidKey, ValueError, TypeError):
        return False

