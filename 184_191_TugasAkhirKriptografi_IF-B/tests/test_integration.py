"""
==============================================================================
SKRIP PENGUJIAN INTEGRASI PENUH (END-TO-END SYSTEM TEST) - TAHAP 7
==============================================================================
Menguji seluruh alur kerja sistem dari hulu ke hilir:
1. Registrasi Akun Pengguna 3FA (Dongle USB + Wajah OpenCV + Hash PBKDF2)
2. Otentikasi Login Pengguna 3FA & Pencatatan Audit ke Blockchain
3. Super Enkripsi Pesan Teks (Vigenère -> AES-256-GCM) & Penyimpanan Data-at-Rest SQLite
4. Enkripsi Berkas Dokumen (ChaCha20-Poly1305) & Pencatatan SHA-256 ke Blockchain
5. Steganografi Multimedia (PNG, WAV, Video FFV1) & Ekstraksi Pesan
6. Verifikasi Akhir Integritas Rantai Blok (validate_chain) dan Basis Data SQLite
==============================================================================
"""

import sys
import shutil
import hashlib
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from modules.auth.auth_manager import register_user, authenticate_user
from modules.cryptography.super_encryption import super_encrypt, super_decrypt
from modules.cryptography.file_cipher import encrypt_file_bytes, decrypt_file_bytes
from modules.database.secure_db import SecureDatabase
from modules.steganography.image_stego import embed_image, extract_image
from modules.steganography.audio_stego import embed_audio, extract_audio, create_dummy_wav
from modules.steganography.video_stego import embed_video, extract_video, create_dummy_video
from modules.blockchain.chain import Blockchain
from tests.test_auth import create_test_face
from config.settings import DATA_DIR, VIRTUAL_DONGLE_DIR


def run_e2e_integration():
    print("=" * 80)
    print("      PENGUJIAN INTEGRASI SISTEM LENGKAP (END-TO-END INTEGRATION TEST)")
    print("=" * 80)
    
    test_env_dir = DATA_DIR / "e2e_runtime"
    if test_env_dir.exists():
        shutil.rmtree(test_env_dir)
    test_env_dir.mkdir(parents=True, exist_ok=True)
    
    db_file = test_env_dir / "e2e_database.db"
    ledger_file = test_env_dir / "e2e_blockchain.json"
    dongle_dir = test_env_dir / "usb_dongle_drive"
    dongle_dir.mkdir(exist_ok=True)
    
    db = SecureDatabase(db_path=db_file)
    blockchain = Blockchain(ledger_path=ledger_file, difficulty=2)
    
    # -------------------------------------------------------------------------
    # LANGKAH 1: REGISTRASI DUA PENGGUNA (ALICE & BOB) DENGAN 3FA
    # -------------------------------------------------------------------------
    print("\n[LANGKAH 1] Pendaftaran Dua Pengguna dengan 3 Faktor Keamanan")
    face_alice = create_test_face(variant=1)
    face_bob = create_test_face(variant=1)
    
    # Daftarkan Alice
    ok_a, msg_a, _ = register_user("alice", "PasswordAlice123!", face_alice, dongle_dir, db=db)
    assert ok_a is True, f"GAGAL: Pendaftaran Alice gagal: {msg_a}"
    print("  * Pengguna 'alice' berhasil didaftarkan (Dongle + Wajah + PBKDF2).")
    
    # Daftarkan Bob
    dongle_bob_dir = test_env_dir / "usb_dongle_bob"
    dongle_bob_dir.mkdir(exist_ok=True)
    ok_b, msg_b, _ = register_user("bob", "PasswordBob456!", face_bob, dongle_bob_dir, db=db)
    assert ok_b is True, f"GAGAL: Pendaftaran Bob gagal: {msg_b}"
    print("  * Pengguna 'bob' berhasil didaftarkan (Dongle + Wajah + PBKDF2).")
    
    # -------------------------------------------------------------------------
    # LANGKAH 2: OTENTIKASI 3FA ALICE & AUDIT TRAIL BLOCKCHAIN
    # -------------------------------------------------------------------------
    print("\n[LANGKAH 2] Otentikasi Login 3FA & Pencatatan Audit Trail ke Blockchain")
    auth_ok, auth_msg, report = authenticate_user(
        username="alice",
        password="PasswordAlice123!",
        face_image_input=face_alice,
        custom_dongle_paths=[dongle_dir],
        db=db
    )
    assert auth_ok is True, f"GAGAL: Otentikasi 3FA Alice gagal: {auth_msg}"
    print("  * Login Alice SUKSES melewati Dongle USB, Verifikasi Wajah, dan Password PBKDF2.")
    
    # Catat audit login ke Blockchain
    b_login = blockchain.record_login_audit("alice", "SUCCESS", report)
    print(f"  * Bukti Login Alice ditambang ke Blockchain: Blok #{b_login.index} [Hash: {b_login.hash[:16]}...]")

    # -------------------------------------------------------------------------
    # LANGKAH 3: PENGIRIMAN PESAN TEKS (SUPER ENKRIPSI + SQLITE + BLOCKCHAIN)
    # -------------------------------------------------------------------------
    print("\n[LANGKAH 3] Pengiriman Pesan Teks (Super Enkripsi: Vigenère + AES-256-GCM)")
    secret_chat = "KODE AKSES PROTOKOL: 'Epsilon-Delta-2026'. Berangkat sekarang!"
    
    # 3A. Super Enkripsi
    enc_info = super_encrypt(secret_chat, vigenere_key="KlasikKey", aes_key="ModernKeyAES", mode="extended")
    print(f"  * Pesan Asli               : '{secret_chat}'")
    print(f"  * Intermediate Vigenère    : {enc_info['intermediate_vigenere'][:30]}...")
    print(f"  * Final Ciphertext AES-GCM : {enc_info['final_ciphertext'][:30]}...")
    
    # 3B. Simpan ke SQLite Terenkripsi (Data-at-Rest)
    msg_id, msg_hash = db.store_message("alice", "bob", "TEXT", secret_chat)
    print(f"  * Pesan tersimpan di SQLite: ID={msg_id}")
    
    # 3C. Catat Bukti Hash ke Blockchain
    b_msg = blockchain.record_message_transaction("alice", "bob", msg_hash, "TEXT_SUPER_ENCRYPTED")
    print(f"  * Hash Pesan ditambang ke Blockchain: Blok #{b_msg.index} [Hash: {b_msg.hash[:16]}...]")
    
    # 3D. Dekripsi Transparan oleh Bob
    convo = db.get_conversation("alice", "bob")
    assert len(convo) == 1
    assert convo[0]["content"] == secret_chat
    assert convo[0]["integrity_verified"] is True
    print("  * Penerima ('bob') berhasil membaca pesan dengan integritas terverifikasi.")

    # -------------------------------------------------------------------------
    # LANGKAH 4: PENGIRIMAN BERKAS (CHACHA20-POLY1305 + BLOCKCHAIN)
    # -------------------------------------------------------------------------
    print("\n[LANGKAH 4] Pengiriman Berkas Dokumen (ChaCha20-Poly1305)")
    doc_bytes = b"%PDF-1.5 Rahasia Perusahaan Dokumen Finansial Kuartal 4"
    enc_doc = encrypt_file_bytes(doc_bytes, "laporan_keuangan.pdf", key="KunciBerkasChaCha777")
    doc_sha256 = hashlib.sha256(enc_doc).hexdigest()
    
    b_file = blockchain.record_file_transaction("alice", "bob", doc_sha256, "laporan_keuangan.pdf")
    print(f"  * Berkas terenkripsi ditambang ke Blockchain: Blok #{b_file.index} [Hash: {b_file.hash[:16]}...]")
    
    # Dekripsi berkas oleh Bob
    rec_bytes, orig_filename, _ = decrypt_file_bytes(enc_doc, key="KunciBerkasChaCha777")
    assert rec_bytes == doc_bytes
    assert orig_filename == "laporan_keuangan.pdf"
    print("  * Berkas berhasil didekripsi dan dipulihkan dengan nama asli yang presisi.")

    # -------------------------------------------------------------------------
    # LANGKAH 5: STEGANOGRAFI MULTIMEDIA (PNG, WAV, VIDEO FFV1)
    # -------------------------------------------------------------------------
    print("\n[LANGKAH 5] Pengujian Steganografi Multimedia (AES-256 + LSB)")
    stego_secret = "PESAN RAHASIA DI DALAM MEDIA MULTIMEDIA 🔒"
    stego_aes_key = "PasswordStegoMultiMedia2026"
    
    # Gambar PNG
    test_img_path = test_env_dir / "carrier.png"
    test_stego_img = test_env_dir / "stego.png"
    from PIL import Image
    import numpy as np
    Image.fromarray(np.ones((100, 100, 3), dtype=np.uint8) * 120).save(test_img_path)
    embed_image(test_img_path, stego_secret, stego_aes_key, test_stego_img)
    recovered_img_text = extract_image(test_stego_img, stego_aes_key)
    assert recovered_img_text == stego_secret
    print("  * Steganografi Gambar PNG: BERHASIL.")
    
    # Audio WAV
    test_wav_path = test_env_dir / "carrier.wav"
    test_stego_wav = test_env_dir / "stego.wav"
    create_dummy_wav(test_wav_path, duration_sec=1.5)
    embed_audio(test_wav_path, stego_secret, stego_aes_key, test_stego_wav)
    recovered_wav_text = extract_audio(test_stego_wav, stego_aes_key)
    assert recovered_wav_text == stego_secret
    print("  * Steganografi Audio WAV: BERHASIL.")
    
    # Video FFV1
    test_vid_path = test_env_dir / "carrier.avi"
    test_stego_vid = test_env_dir / "stego.avi"
    create_dummy_video(test_vid_path, num_frames=10)
    embed_video(test_vid_path, stego_secret, stego_aes_key, test_stego_vid)
    recovered_vid_text = extract_video(test_stego_vid, stego_aes_key)
    assert recovered_vid_text == stego_secret
    print("  * Steganografi Video Lossless FFV1: BERHASIL.")

    # -------------------------------------------------------------------------
    # LANGKAH 6: AUDIT AKHIR KEUTUHAN RANTAI BLOCKCHAIN DAN BASIS DATA
    # -------------------------------------------------------------------------
    print("\n[LANGKAH 6] Audit Akhir Integritas Seluruh Sistem")
    
    # Audit Blockchain
    bc_valid, bc_msg, broken = blockchain.validate_chain()
    print(f"  * Audit Blockchain : {bc_msg}")
    assert bc_valid is True, "GAGAL: Integritas rantai blok harus valid 100%!"
    
    # Audit SQLite
    db_clean, total_rows, corrupted = db.verify_all_records_integrity()
    print(f"  * Audit SQLite     : {total_rows} pesan terverifikasi bersih (Corrupted: {corrupted}).")
    assert db_clean is True, "GAGAL: Integritas SQLite harus valid 100%!"
    
    print("\n" + "=" * 80)
    print(" SELURUH PENGUJIAN INTEGRASI SISTEM (TAHAP 7) SUKSES 100%!")
    print(" APLIKASI SECURE MESSENGER SIAP DIJALANKAN MELALUI STREAMLIT: `streamlit run app.py`")
    print("=" * 80)


if __name__ == "__main__":
    run_e2e_integration()
