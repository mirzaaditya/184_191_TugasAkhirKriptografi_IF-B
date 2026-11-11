"""
==============================================================================
SKRIP PENGUJIAN OTOMATIS: MODUL ENKRIPSI TEKS & BERKAS (TAHAP 3)
==============================================================================
Menjalankan serangkaian pengujian komprehensif:
1. Uji Vigenère Cipher (Klasik): Modulo 26 alfabetik & Extended Byte (Unicode/Emoji)
2. Uji AES-256-GCM (Modern AEAD): Kerahasiaan, Nonce Unik, Integritas Tag
3. Uji Super Enkripsi Teks: Pipeline Vigenère + AES-256-GCM, uji kunci salah & tampering
4. Uji Enkripsi File ChaCha20-Poly1305: Berkas biner, pemulihan nama file, uji manipulasi
==============================================================================
"""

import sys
import os
import hashlib
from pathlib import Path

# Tambahkan root proyek ke sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from modules.cryptography.classical import (
    vigenere_encrypt,
    vigenere_decrypt,
    vigenere_encrypt_alphabetic,
    vigenere_decrypt_alphabetic
)
from modules.cryptography.modern import (
    aes_encrypt,
    aes_decrypt_text,
    derive_aes_key
)
from modules.cryptography.super_encryption import (
    super_encrypt,
    super_decrypt
)
from modules.cryptography.file_cipher import (
    encrypt_file_bytes,
    decrypt_file_bytes,
    encrypt_file,
    decrypt_file
)
from config.settings import DATA_DIR


def run_tests():
    print("=" * 75)
    print("     PENGUJIAN MODUL SUPER ENKRIPSI & ENKRIPSI BERKAS (TAHAP 3)")
    print("=" * 75)
    
    # -------------------------------------------------------------------------
    # UJI 1: VIGENÈRE CIPHER (KLASIK)
    # -------------------------------------------------------------------------
    print("\n[UJI 1] Kriptografi Klasik: Vigenère Cipher")
    
    # 1A. Mode Alfabet Tradisional
    plain_alpha = "ATTACK AT DAWN"
    key_alpha = "LEMON"
    cipher_alpha = vigenere_encrypt_alphabetic(plain_alpha, key_alpha)
    dec_alpha = vigenere_decrypt_alphabetic(cipher_alpha, key_alpha)
    print(f"  * Mode Alfabetik Plaintext : '{plain_alpha}'")
    print(f"  * Kunci Alfabetik          : '{key_alpha}'")
    print(f"  * Ciphertext Alfabetik     : '{cipher_alpha}'")
    assert cipher_alpha == "LXFOPV EF RNHR", "GAGAL: Vektor uji Vigenère standar tidak cocok!"
    assert dec_alpha == plain_alpha, "GAGAL: Dekripsi Vigenère alfabetik gagal memulihkan teks!"
    print("  [PASSED] Vektor uji Vigenère tradisional (ATTACK AT DAWN -> LXFOPV EF RNHR) 100% Cocok.")
    
    # 1B. Mode Extended Byte (Simbol, Angka, Spasi, Emoji)
    plain_extended = "Pesan Rahasia #007: Operasi Malam Hari Berhasil! 🛡️🔐"
    key_extended = "KunciSuperRahasia2026"
    cipher_ext = vigenere_encrypt(plain_extended, key_extended, mode="extended")
    dec_ext = vigenere_decrypt(cipher_ext, key_extended, mode="extended")
    print(f"  * Extended Plaintext (Emoji): '{plain_extended}'")
    print(f"  * Extended Ciphertext (B64) : {cipher_ext[:35]}... (terpotong)")
    assert dec_ext == plain_extended, "GAGAL: Extended Vigenère gagal memulihkan teks dengan simbol/emoji!"
    print("  [PASSED] Extended Byte Vigenère berhasil mengenkripsi & mendekripsi karakter kompleks.")

    # -------------------------------------------------------------------------
    # UJI 2: AES-256-GCM (MODERN AEAD)
    # -------------------------------------------------------------------------
    print("\n[UJI 2] Kriptografi Modern: AES-256-GCM (Authenticated Encryption)")
    secret_text = "Koordinat target: -6.2088, 106.8456. Mulai penyusupan pukul 02:00 WIB."
    aes_pass = "MasterAESPassword@Secure99"
    
    c1 = aes_encrypt(secret_text, aes_pass)
    c2 = aes_encrypt(secret_text, aes_pass)
    
    # Buktikan Nonce acak menjamin kerahasiaan probabilistik
    assert c1 != c2, "GAGAL: Enkripsi teks yang sama harus menghasilkan ciphertext berbeda berkat Nonce acak!"
    print("  [PASSED] Dua enkripsi teks identik menghasilkan ciphertext berbeda (mencegah analisis pola replay).")
    
    # Dekripsi sukses
    recovered_aes = aes_decrypt_text(c1, aes_pass)
    assert recovered_aes == secret_text, "GAGAL: Dekripsi AES-256-GCM gagal memulihkan teks!"
    print("  [PASSED] Dekripsi AES-256-GCM berhasil dengan keutuhan 100%.")
    
    # Uji Tampering (Integritas Tag GCM)
    tampered_c1 = c1[:-4] + "AAAA"  # Ubah beberapa karakter tag di akhir
    try:
        aes_decrypt_text(tampered_c1, aes_pass)
        assert False, "GAGAL: Modifikasi ciphertext harus memicu InvalidTag!"
    except ValueError as e:
        print(f"  * Uji Tampering AES Terdeteksi: {e}")
        print("  [PASSED] Serangan manipulasi data berhasil digagalkan oleh AES-GCM Authentication Tag.")

    # -------------------------------------------------------------------------
    # UJI 3: SUPER ENKRIPSI (VIGENÈRE + AES-256-GCM)
    # -------------------------------------------------------------------------
    print("\n[UJI 3] Super Enkripsi Pesan Teks (Vigenère -> AES-256-GCM)")
    msg_top_secret = "DOKUMEN RAHASIA NEGARA: Proyek Antariksa Garuda 2026 telah disetujui."
    k_vig = "KriptoKlasik"
    k_aes = "SandiModern256Bit"
    
    # Eksekusi Super Enkripsi
    enc_result = super_encrypt(msg_top_secret, k_vig, k_aes, mode="extended")
    print(f"  * Plaintext Asli              : '{msg_top_secret}'")
    print(f"  * Intermediate (Vigenère)     : {enc_result['intermediate_vigenere'][:35]}...")
    print(f"  * Final Ciphertext (AES-GCM)  : {enc_result['final_ciphertext'][:35]}...")
    print(f"  * Waktu Eksekusi Enkripsi     : {enc_result['encryption_time_ms']} ms")
    
    # Eksekusi Super Dekripsi Sukses
    dec_result = super_decrypt(enc_result['final_ciphertext'], k_vig, k_aes, mode="extended")
    assert dec_result['plaintext'] == msg_top_secret, "GAGAL: Super enkripsi gagal memulihkan plaintext asli!"
    print("  [PASSED] Super Dekripsi sukses memulihkan pesan asli secara bertahap.")
    
    # Skenario Kunci AES Salah
    try:
        super_decrypt(enc_result['final_ciphertext'], k_vig, "PasswordAESYangSalah", mode="extended")
        assert False, "GAGAL: Kunci AES salah harus ditolak pada lapisan pertama!"
    except ValueError:
        print("  [PASSED] Lapisan 1 (AES-GCM) memblokir dekripsi seketika saat kunci modern salah.")
        
    # Skenario Kunci Vigenère Salah
    wrong_vig_res = super_decrypt(enc_result['final_ciphertext'], "KunciVigenereSalah", k_aes, mode="extended")
    assert wrong_vig_res['plaintext'] != msg_top_secret, "GAGAL: Kunci Vigenère salah seharusnya menghasilkan teks acak!"
    print("  [PASSED] Lapisan 2 (Vigenère) menghasilkan teks acak/gibberish saat kunci klasik salah.")

    # -------------------------------------------------------------------------
    # UJI 4: ENKRIPSI BERKAS DENGAN CHACHA20-POLY1305
    # -------------------------------------------------------------------------
    print("\n[UJI 4] Enkripsi Berkas Biner: ChaCha20-Poly1305 (AEAD Stream Cipher)")
    test_files_dir = DATA_DIR / "test_files"
    test_files_dir.mkdir(parents=True, exist_ok=True)
    
    # Buat file biner dummy (simulasi dokumen/gambar)
    orig_file = test_files_dir / "laporan_rahasia.pdf"
    enc_file = test_files_dir / "laporan_rahasia.pdf.enc"
    dec_file = test_files_dir / "recovered_laporan.pdf"
    
    sample_binary_content = b"%PDF-1.4 Mock Binary Content " + os.urandom(2048) + b" END_OF_FILE"
    orig_file.write_bytes(sample_binary_content)
    orig_sha256 = hashlib.sha256(sample_binary_content).hexdigest()
    
    file_pass = "ChaCha20FileSpecialKey#777"
    
    # Enkripsi Berkas
    f_enc_info = encrypt_file(orig_file, enc_file, file_pass)
    print(f"  * Berkas Asli       : {orig_file.name} ({f_enc_info['original_size']} bytes)")
    print(f"  * Berkas Terenkripsi: {enc_file.name} ({f_enc_info['encrypted_size']} bytes)")
    print(f"  * Algoritma         : {f_enc_info['algorithm']}")
    
    # Dekripsi Berkas
    f_dec_info = decrypt_file(enc_file, dec_file, file_pass)
    recovered_content = dec_file.read_bytes()
    recovered_sha256 = hashlib.sha256(recovered_content).hexdigest()
    
    print(f"  * Berkas Dipulihkan : {f_dec_info['filename']} ({f_dec_info['recovered_size']} bytes)")
    assert orig_sha256 == recovered_sha256, "GAGAL: SHA-256 berkas hasil dekripsi tidak cocok dengan aslinya!"
    print(f"  * Verifikasi Hash   : SHA-256 Asli == SHA-256 Pulih ({recovered_sha256[:16]}...)")
    print("  [PASSED] Berkas berhasil didekripsi dengan integritas byte-for-byte sempurna.")
    
    # Uji Tampering Berkas: Ubah 1 byte di dalam file terenkripsi
    tamper_enc = bytearray(enc_file.read_bytes())
    tamper_enc[-10] ^= 0xFF  # Flip bit pada Poly1305 authentication tag
    tampered_file = test_files_dir / "tampered.enc"
    tampered_file.write_bytes(tamper_enc)
    
    try:
        decrypt_file(tampered_file, test_files_dir / "should_fail.pdf", file_pass)
        assert False, "GAGAL: Berkas yang dimanipulasi harus ditolak oleh Poly1305!"
    except ValueError as e:
        print(f"  * Uji Tampering Berkas: {e}")
        print("  [PASSED] Manipulasi isi berkas terdeteksi dan digagalkan oleh ChaCha20-Poly1305.")

    print("\n" + "=" * 75)
    print(" SELURUH PENGUJIAN TAHAP 3 BERHASIL 100%! ENKRIPSI TEKS & BERKAS SIAP.")
    print("=" * 75)


if __name__ == "__main__":
    run_tests()
