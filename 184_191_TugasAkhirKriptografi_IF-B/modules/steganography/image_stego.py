"""
==============================================================================
MODUL: STEGANOGRAFI GAMBAR - LSB PADA CITRA PNG (PILLOW + NUMPY)
==============================================================================
Deskripsi:
Modul ini menyembunyikan pesan rahasia yang telah dienkripsi AES-256-GCM ke dalam
bit terkecil (Least Significant Bit - LSB) dari saluran warna piksel citra PNG.

Mengapa Format PNG?
PNG menggunakan algoritma kompresi lossless (Deflate: LZ77 + Huffman Coding),
sehingga nilai piksel tidak pernah berubah atau mengalami distorsi.
Format lossy seperti JPEG TIDAK BISA digunakan untuk LSB karena kompresi DCT
dan kuantisasi akan merusak nilai bit LSB.
==============================================================================
"""

import numpy as np
from pathlib import Path
from PIL import Image
from modules.steganography.stego_common import (
    bytes_to_bits,
    bits_to_bytes,
    prepare_encrypted_payload,
    decrypt_extracted_payload,
    HEADER_SIZE_BYTES
)


def embed_image(
    carrier_image_path: str | Path,
    secret_message: str | bytes,
    aes_key: str | bytes,
    output_image_path: str | Path
) -> dict:
    """
    Menyisipkan pesan rahasia terenkripsi AES ke dalam citra pembawa PNG menggunakan LSB.
    
    Args:
        carrier_image_path: Path citra pembawa (PNG, JPG, BMP).
        secret_message: Teks atau data rahasia yang akan disembunyikan.
        aes_key: Kunci enkripsi AES-256.
        output_image_path: Path tujuan penyimpanan citra stego (harus berformat .png).
        
    Returns:
        dict: Informasi teknis steganografi (kapasitas, bit terpakai, PSNR).
    """
    carrier_path = Path(carrier_image_path)
    if not carrier_path.exists():
        raise FileNotFoundError(f"Citra pembawa '{carrier_path}' tidak ditemukan.")
        
    out_path = Path(output_image_path)
    if out_path.suffix.lower() != ".png":
        out_path = out_path.with_suffix(".png")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    
    # 1. Enkripsi pesan dengan AES-256-GCM dan kemas payload
    payload_bytes = prepare_encrypted_payload(secret_message, aes_key)
    payload_bits = bytes_to_bits(payload_bytes)
    total_bits_needed = len(payload_bits)
    
    # 2. Buka citra pembawa menggunakan Pillow dan konversi ke NumPy
    with Image.open(carrier_path) as img:
        img_rgb = img.convert("RGB")
        img_arr = np.array(img_rgb, dtype=np.uint8)
        
    orig_shape = img_arr.shape
    total_available_bits = img_arr.size  # H * W * 3
    
    # 3. Pemeriksaan Kapasitas Media
    if total_bits_needed > total_available_bits:
        raise ValueError(
            f"Kapasitas citra tidak cukup! Dibutuhkan {total_bits_needed} bits ({len(payload_bytes)} bytes), "
            f"tetapi kapasitas maksimal citra hanya {total_available_bits} bits ({total_available_bits // 8} bytes)."
        )
        
    # 4. Operasi Penyisipan LSB Tervektorisasi (NumPy Vectorized LSB Insertion)
    flat_pixels = img_arr.flatten()
    bits_np = np.array(payload_bits, dtype=np.uint8)
    
    # Bersihkan bit terakhir (& ~1) lalu timpa dengan bit rahasia (| bit)
    flat_pixels[:total_bits_needed] = (flat_pixels[:total_bits_needed] & 0xFE) | bits_np
    
    stego_arr = flat_pixels.reshape(orig_shape)
    
    # 5. Simpan citra stego sebagai PNG lossless
    stego_img = Image.fromarray(stego_arr, mode="RGB")
    stego_img.save(str(out_path), format="PNG", optimize=False)
    
    # 6. Hitung rasio pemakaian kapasitas
    usage_percent = (total_bits_needed / total_available_bits) * 100
    
    return {
        "status": "success",
        "output_path": str(out_path),
        "payload_bytes": len(payload_bytes),
        "embedded_bits": total_bits_needed,
        "carrier_capacity_bits": total_available_bits,
        "capacity_usage_percent": round(usage_percent, 2),
        "dimensions": f"{orig_shape[1]}x{orig_shape[0]} px (RGB)"
    }


def extract_image(
    stego_image_path: str | Path,
    aes_key: str | bytes
) -> str:
    """
    Mengekstrak bit LSB dari citra PNG dan mendekripsi pesan rahasia dengan AES-256-GCM.
    
    Args:
        stego_image_path: Path berkas citra PNG yang memuat pesan stego.
        aes_key: Kunci dekripsi AES-256.
        
    Returns:
        str: Pesan rahasia asli hasil ekstraksi dan dekripsi.
    """
    path = Path(stego_image_path)
    if not path.exists():
        raise FileNotFoundError(f"Berkas citra stego '{path}' tidak ditemukan.")
        
    with Image.open(path) as img:
        img_rgb = img.convert("RGB")
        img_arr = np.array(img_rgb, dtype=np.uint8)
        
    flat_pixels = img_arr.flatten()
    
    # 1. Ekstraksi 64 bit pertama (8 bytes header: 4B Magic + 4B Length)
    header_bits = (flat_pixels[:64] & 1).tolist()
    header_bytes = bits_to_bytes(header_bits)
    
    if len(header_bytes) < HEADER_SIZE_BYTES or header_bytes[:4] != b"SMSG":
        raise ValueError("Citra ini tidak memuat pesan steganografi yang valid (Header SMSG tidak ditemukan).")
        
    import struct
    payload_len = struct.unpack(">I", header_bytes[4:8])[0]
    total_bytes = HEADER_SIZE_BYTES + payload_len
    total_bits = total_bytes * 8
    
    if total_bits > flat_pixels.size:
        raise ValueError("Data ukuran steganografi tidak wajar atau melebihi kapasitas citra.")
        
    # 2. Ekstraksi seluruh bit payload secara presisi
    all_bits = (flat_pixels[:total_bits] & 1).tolist()
    all_bytes = bits_to_bytes(all_bits)
    
    # 3. Dekripsi AES-256-GCM dan verifikasi authentication tag
    return decrypt_extracted_payload(all_bytes, aes_key)
