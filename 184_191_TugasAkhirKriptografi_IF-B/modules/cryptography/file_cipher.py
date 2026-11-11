"""
==============================================================================
MODUL: ENKRIPSI FILE - CHACHA20-POLY1305 (STREAM CIPHER AEAD)
==============================================================================
Deskripsi:
Modul ini mengamankan pengiriman dan penyimpanan berkas (dokumen, gambar, binary)
menggunakan algoritma yang berbeda dari pesan teks: ChaCha20-Poly1305 (RFC 8439).

Mengapa ChaCha20-Poly1305 untuk Berkas?
1. Stream Cipher Modern: Beroperasi sangat cepat pada data biner berukuran besar.
2. Kebal Cache-Timing Attack: Dirancang tanpa S-Box berbasis tabel memori,
   sehingga secara alami tahan terhadap serangan side-channel waktu CPU.
3. AEAD (Authenticated Encryption): Memadukan stream cipher ChaCha20 dengan
   Poly1305 MAC 128-bit untuk memastikan berkas tidak rusak atau diubah (tampered).
4. Pemisahan Kunci & Algoritma: Memenuhi aturan dosen agar algoritma enkripsi berkas
   sepenuhnya terpisah dan independen dari cipher pesan teks (AES-256-GCM).
==============================================================================
"""

import os
import json
import struct
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

# Header Magic Bytes untuk identifikasi format berkas terenkripsi
FILE_MAGIC_HEADER = b"SMSG_ENCF"  # 9 Bytes
FILE_FORMAT_VERSION = 1            # 1 Byte


def derive_file_key(passphrase_or_key: str | bytes) -> bytes:
    """
    Menghasilkan kunci 256-bit (tepat 32 bytes) khusus modul berkas.
    Menggunakan domain separation tag agar kunci file tidak pernah identik
    dengan kunci pesan teks meskipun passphrase yang dimasukkan pengguna sama.
    """
    if isinstance(passphrase_or_key, str):
        passphrase_or_key = passphrase_or_key.encode("utf-8")
        
    # Domain separation: tambahkan prefix khusus konteks file
    hasher = hashlib.sha256()
    hasher.update(b"DOMAIN_FILE_ENCRYPTION_CHACHA20_KEY")
    hasher.update(passphrase_or_key)
    return hasher.digest()


def encrypt_file_bytes(
    file_bytes: bytes,
    original_filename: str,
    key: str | bytes
) -> bytes:
    """
    Mengenkripsi byte biner suatu berkas beserta metadata nama file aslinya.
    
    Format Kontainer Berkas Terenkripsi:
    [MAGIC: 9B] + [VER: 1B] + [NONCE: 12B] + [META_LEN: 4B] + [CIPHERTEXT_WITH_TAG]
    (Metadata nama berkas dienkripsi bersama dengan konten agar terlindungi).
    
    Args:
        file_bytes (bytes): Konten biner berkas asli.
        original_filename (str): Nama berkas asli (misal: "laporan_keuangan.pdf").
        key (str | bytes): Kunci enkripsi atau passphrase.
        
    Returns:
        bytes: Seluruh kontainer berkas terenkripsi.
    """
    if not file_bytes:
        raise ValueError("Konten berkas tidak boleh kosong (0 byte).")
        
    file_key = derive_file_key(key)
    chacha = ChaCha20Poly1305(file_key)
    
    # Nonce acak 96-bit (12 bytes) sesuai RFC 8439
    nonce = os.urandom(12)
    
    # Kemas metadata asli ke dalam JSON
    meta_dict = {
        "filename": original_filename,
        "original_size": len(file_bytes)
    }
    meta_json = json.dumps(meta_dict).encode("utf-8")
    meta_len = len(meta_json)
    
    # Struktur data internal yang dienkripsi: [4-byte meta_len] + [metadata_json] + [file_bytes]
    inner_payload = struct.pack(">I", meta_len) + meta_json + file_bytes
    
    # Associated Data (AAD) untuk mengunci keaslian header kontainer
    aad_header = FILE_MAGIC_HEADER + bytes([FILE_FORMAT_VERSION]) + nonce
    
    # Enkripsi AEAD
    ciphertext_with_tag = chacha.encrypt(nonce, inner_payload, associated_data=aad_header)
    
    # Gabungkan header kontainer + payload terenkripsi
    return aad_header + ciphertext_with_tag


def decrypt_file_bytes(
    encrypted_container_bytes: bytes,
    key: str | bytes
) -> tuple[bytes, str, dict]:
    """
    Mendekripsi kontainer berkas terenkripsi dan memvalidasi keutuhan datanya.
    
    Args:
        encrypted_container_bytes (bytes): Konten biner terenkripsi.
        key (str | bytes): Kunci dekripsi atau passphrase.
        
    Returns:
        tuple[bytes, str, dict]: (Byte Berkas Asli, Nama File Asli, Metadata Berkas)
        
    Raises:
        ValueError: Jika format berkas salah, kunci salah, atau berkas telah rusak/dimodifikasi.
    """
    min_header_len = len(FILE_MAGIC_HEADER) + 1 + 12 + 16  # Magic + Ver + Nonce + Min Poly1305 Tag
    if len(encrypted_container_bytes) < min_header_len:
        raise ValueError("Berkas terenkripsi rusak atau ukurannya terlalu kecil untuk diproses.")
        
    # Periksa magic header
    magic_len = len(FILE_MAGIC_HEADER)
    magic = encrypted_container_bytes[:magic_len]
    if magic != FILE_MAGIC_HEADER:
        raise ValueError("Format berkas tidak dikenali (bukan kontainer terenkripsi SMSG yang valid).")
        
    version = encrypted_container_bytes[magic_len]
    if version != FILE_FORMAT_VERSION:
        raise ValueError(f"Versi format berkas ({version}) tidak didukung oleh modul ini.")
        
    nonce = encrypted_container_bytes[magic_len + 1 : magic_len + 1 + 12]
    aad_header = encrypted_container_bytes[: magic_len + 1 + 12]
    ciphertext_with_tag = encrypted_container_bytes[magic_len + 1 + 12 :]
    
    file_key = derive_file_key(key)
    chacha = ChaCha20Poly1305(file_key)
    
    try:
        decrypted_payload = chacha.decrypt(nonce, ciphertext_with_tag, associated_data=aad_header)
    except InvalidTag:
        raise ValueError("DEKRIPSI BERKAS GAGAL: Kunci salah atau isi berkas telah dimanipulasi / rusak!")
        
    # Ekstraksi metadata internal
    if len(decrypted_payload) < 4:
        raise ValueError("Struktur payload internal rusak.")
        
    meta_len = struct.unpack(">I", decrypted_payload[:4])[0]
    meta_json_bytes = decrypted_payload[4 : 4 + meta_len]
    raw_file_bytes = decrypted_payload[4 + meta_len :]
    
    try:
        metadata = json.loads(meta_json_bytes.decode("utf-8"))
        original_filename = metadata.get("filename", "recovered_file.bin")
    except Exception:
        original_filename = "recovered_file.bin"
        metadata = {"filename": original_filename, "original_size": len(raw_file_bytes)}
        
    return raw_file_bytes, original_filename, metadata


def encrypt_file(
    source_file_path: str | Path,
    output_file_path: str | Path,
    key: str | bytes
) -> dict:
    """
    Mengenkripsi berkas fisik di disk dan menyimpannya ke berkas target baru (.enc).
    """
    src = Path(source_file_path)
    if not src.exists() or not src.is_file():
        raise FileNotFoundError(f"Berkas sumber '{src}' tidak ditemukan.")
        
    with open(src, "rb") as f:
        data = f.read()
        
    enc_bytes = encrypt_file_bytes(data, src.name, key)
    
    dst = Path(output_file_path)
    dst.parent.mkdir(parents=True, exist_ok=True)
    with open(dst, "wb") as f:
        f.write(enc_bytes)
        
    return {
        "status": "success",
        "source": str(src),
        "destination": str(dst),
        "original_size": len(data),
        "encrypted_size": len(enc_bytes),
        "algorithm": "ChaCha20-Poly1305 (AEAD)"
    }


def decrypt_file(
    encrypted_file_path: str | Path,
    output_dir_or_file: str | Path,
    key: str | bytes
) -> dict:
    """
    Mendekripsi berkas fisik dari disk dan memulihkan nama berkas aslinya.
    """
    enc_path = Path(encrypted_file_path)
    if not enc_path.exists() or not enc_path.is_file():
        raise FileNotFoundError(f"Berkas terenkripsi '{enc_path}' tidak ditemukan.")
        
    with open(enc_path, "rb") as f:
        enc_data = f.read()
        
    raw_bytes, orig_filename, meta = decrypt_file_bytes(enc_data, key)
    
    out_target = Path(output_dir_or_file)
    if out_target.is_dir() or (not out_target.suffix and not out_target.exists()):
        out_target.mkdir(parents=True, exist_ok=True)
        final_path = out_target / orig_filename
    else:
        out_target.parent.mkdir(parents=True, exist_ok=True)
        final_path = out_target
        
    with open(final_path, "wb") as f:
        f.write(raw_bytes)
        
    return {
        "status": "success",
        "recovered_file": str(final_path),
        "filename": orig_filename,
        "recovered_size": len(raw_bytes),
        "metadata": meta
    }

