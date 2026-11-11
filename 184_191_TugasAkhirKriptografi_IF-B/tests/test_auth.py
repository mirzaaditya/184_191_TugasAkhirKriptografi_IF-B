"""
==============================================================================
SKRIP PENGUJIAN OTOMATIS: MODUL AUTENTIKASI (TAHAP 2)
==============================================================================
Menjalankan serangkaian skenario pengujian komprehensif:
1. Uji Kriptografi Password (PBKDF2-HMAC-SHA256, Salt, Constant-time verification)
2. Uji Hardware Dongle (Pembuatan kunci, verifikasi valid, manipulasi file / tampered)
3. Uji Biometrik OpenCV (Deteksi wajah, pendaftaran rujukan, verifikasi kemiripan)
4. Uji Integrasi 3-Factor Authentication (Skenario sukses, password salah, dongle hilang)
==============================================================================
"""

import sys
import os
import shutil
import cv2
import numpy as np
from pathlib import Path

# Tambahkan root proyek ke sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from modules.auth.hasher import hash_password, verify_password
from modules.auth.dongle import generate_dongle_key, verify_dongle
from modules.auth.biometric import detect_and_crop_face, register_reference_face, verify_face
from modules.auth.auth_manager import register_user, authenticate_user
from config.settings import DATA_DIR, VIRTUAL_DONGLE_DIR, DONGLE_KEY_FILENAME


def create_test_face(variant: int = 1) -> np.ndarray:
    """Membuat citra wajah sintetis untuk pengujian otomatis deterministik."""
    img = np.ones((300, 300, 3), dtype=np.uint8) * 255
    if variant == 1:
        # Karakter Wajah 1 (User Alice)
        cv2.ellipse(img, (150, 150), (80, 110), 0, 0, 360, (200, 200, 200), -1)
        cv2.circle(img, (120, 120), 12, (50, 50, 50), -1)
        cv2.circle(img, (180, 120), 12, (50, 50, 50), -1)
        cv2.line(img, (150, 130), (150, 160), (30, 30, 30), 3)
        cv2.ellipse(img, (150, 190), (30, 15), 0, 0, 180, (40, 40, 40), 4)
    elif variant == 2:
        # Karakter Wajah 2 (Orang lain / User Bob)
        cv2.ellipse(img, (150, 150), (70, 95), 0, 0, 360, (180, 180, 180), -1)
        cv2.rectangle(img, (110, 110), (135, 125), (20, 20, 20), -1)
        cv2.rectangle(img, (165, 110), (190, 125), (20, 20, 20), -1)
        cv2.line(img, (150, 125), (150, 165), (20, 20, 20), 4)
        cv2.line(img, (130, 200), (170, 200), (20, 20, 20), 5)
    else:
        # Citra kosong tanpa wajah
        pass
    return img


def run_tests():
    print("=" * 75)
    print("         PENGUJIAN MODUL AUTENTIKASI (TAHAP 2) - SECURE MESSENGER")
    print("=" * 75)
    
    # Bersihkan data uji lama agar pengujian bersifat idempoten
    from modules.auth.auth_manager import USER_REGISTRY_FILE
    if USER_REGISTRY_FILE.exists():
        USER_REGISTRY_FILE.unlink()
    
    # -------------------------------------------------------------------------
    # UJI 1: PBKDF2 PASSWORD HASHER
    # -------------------------------------------------------------------------
    print("\n[UJI 1] Kriptografi Kata Sandi: PBKDF2-HMAC-SHA256")
    raw_pwd = "SuperSecretPassword123!"
    hash1, salt1 = hash_password(raw_pwd)
    hash2, salt2 = hash_password(raw_pwd)
    
    print(f"  * Password Asli    : {raw_pwd}")
    print(f"  * Salt 1 (16 bytes): {salt1}")
    print(f"  * Hash 1 (256 bit) : {hash1[:32]}... (terpotong)")
    print(f"  * Salt 2 (acak)    : {salt2}")
    print(f"  * Hash 2 (unik)    : {hash2[:32]}... (terpotong)")
    
    # Buktikan bahwa 2 password yang sama menghasilkan hash berbeda karena salt acak
    assert hash1 != hash2, "GAGAL: Salt tidak menghasilkan hash unik!"
    print("  [PASSED] Dua password identik menghasilkan hash berbeda berkat salt unik (Anti-Rainbow Table).")
    
    # Verifikasi password benar & salah
    assert verify_password(raw_pwd, salt1, hash1) is True, "GAGAL: Password benar harus valid!"
    assert verify_password("SalahPassword", salt1, hash1) is False, "GAGAL: Password salah harus ditolak!"
    print("  [PASSED] Verifikasi password benar sukses, dan password salah ditolak dengan tepat.")
    
    # -------------------------------------------------------------------------
    # UJI 2: HARDWARE DONGLE VALIDATOR (USB TOKEN)
    # -------------------------------------------------------------------------
    print("\n[UJI 2] Hardware Dongle USB & Validasi Kunci Digital (HMAC + AES-256)")
    test_dongle_dir = VIRTUAL_DONGLE_DIR
    test_user = "alice"
    
    # Buat kunci dongle baru
    key_file = generate_dongle_key(test_dongle_dir, test_user)
    print(f"  * File Kunci Dibuat : {key_file.name} pada {test_dongle_dir}")
    assert key_file.exists(), "GAGAL: File kunci dongle tidak ditemukan."
    
    # Verifikasi kunci asli
    ok, msg, data = verify_dongle(username=test_user, custom_search_paths=[test_dongle_dir])
    print(f"  * Status Dongle Asli: {ok} -> {msg}")
    assert ok is True, f"GAGAL: Dongle asli harus valid! Pesan: {msg}"
    print("  [PASSED] Dongle USB asli berhasil divalidasi dan token AES didekripsi sempurna.")
    
    # Uji manipulasi (Tampering attack): ubah isi file tanpa memperbarui HMAC signature
    tamper_file = test_dongle_dir / DONGLE_KEY_FILENAME
    content = tamper_file.read_text(encoding="utf-8")
    tampered_content = content.replace("alice", "hacker_mallory")
    tamper_file.write_text(tampered_content, encoding="utf-8")
    
    tamper_ok, tamper_msg, _ = verify_dongle(username="hacker_mallory", custom_search_paths=[test_dongle_dir])
    print(f"  * Uji File Dimanipulasi: Status={tamper_ok} -> {tamper_msg}")
    assert tamper_ok is False, "GAGAL: File kunci yang dimanipulasi harus ditolak oleh HMAC!"
    print("  [PASSED] Serangan manipulasi data dongle berhasil digagalkan oleh tanda tangan digital HMAC-SHA256.")
    
    # Pulihkan file kunci asli
    generate_dongle_key(test_dongle_dir, test_user)
    
    # -------------------------------------------------------------------------
    # UJI 3: BIOMETRIK WAJAH DENGAN OPENCV
    # -------------------------------------------------------------------------
    print("\n[UJI 3] Biometrik Pengenalan Wajah dengan OpenCV")
    face_alice_reg = create_test_face(variant=1)
    face_alice_live = create_test_face(variant=1)
    face_bob_imposter = create_test_face(variant=2)
    blank_canvas = create_test_face(variant=3)
    
    # Registrasi wajah rujukan
    reg_ok, reg_msg, ref_path = register_reference_face(test_user, face_alice_reg)
    print(f"  * Pendaftaran Wajah : {reg_ok} -> {reg_msg}")
    assert reg_ok is True, "GAGAL: Registrasi rujukan wajah gagal."
    
    # Verifikasi wajah pemilik asli
    v_ok, v_msg, score = verify_face(test_user, face_alice_live)
    print(f"  * Verifikasi Wajah Asli: {v_ok} (Kemiripan: {score*100:.1f}%) -> {v_msg}")
    assert v_ok is True, "GAGAL: Wajah pemilik sah harus lolos!"
    print("  [PASSED] Wajah pemilik asli dikenali dan lolos verifikasi.")
    
    # Verifikasi wajah penipu (imposter / Bob)
    imp_ok, imp_msg, imp_score = verify_face(test_user, face_bob_imposter)
    print(f"  * Verifikasi Imposter  : {imp_ok} (Kemiripan: {imp_score*100:.1f}%) -> {imp_msg}")
    assert imp_ok is False, "GAGAL: Wajah orang lain harus ditolak!"
    print("  [PASSED] Penipu ditolak karena kemiripan wajah berada di bawah ambang batas.")
    
    # Verifikasi frame kosong tanpa wajah
    blank_ok, blank_msg, _ = verify_face(test_user, blank_canvas)
    print(f"  * Frame Tanpa Wajah   : {blank_ok} -> {blank_msg}")
    assert blank_ok is False, "GAGAL: Frame tanpa wajah harus ditolak!"
    print("  [PASSED] Deteksi wajah menolak citra kosong.")
    
    # -------------------------------------------------------------------------
    # UJI 4: INTEGRASI 3-FACTOR AUTHENTICATION (AUTH MANAGER)
    # -------------------------------------------------------------------------
    print("\n[UJI 4] Integrasi 3-Factor Authentication (Dongle + Wajah + Password)")
    user_charlie = "charlie"
    pwd_charlie = "RahasiaNegara@2026"
    face_charlie = create_test_face(variant=1)
    
    # Daftarkan pengguna baru dengan 3 faktor sekaligus
    reg_res, reg_txt, _ = register_user(
        username=user_charlie,
        password=pwd_charlie,
        face_image_input=face_charlie,
        dongle_target_path=test_dongle_dir
    )
    print(f"  * Pendaftaran 3FA: {reg_res} -> {reg_txt}")
    assert reg_res is True, "GAGAL: Pendaftaran 3FA harus sukses."
    
    # Skenario A: Semua 3 faktor benar -> SUKSES
    auth_ok, auth_msg, report = authenticate_user(
        username=user_charlie,
        password=pwd_charlie,
        face_image_input=face_charlie,
        custom_dongle_paths=[test_dongle_dir]
    )
    print(f"  * Skenario Sukses (3 Faktor Valid): {auth_ok} -> {auth_msg}")
    assert auth_ok is True, "GAGAL: Login dengan 3 faktor valid harus berhasil."
    print("  [PASSED] Otentikasi sukses penuh ketika ketiga faktor terpenuhi.")
    
    # Skenario B: Password salah -> GAGAL
    wrong_pwd_ok, wrong_pwd_msg, _ = authenticate_user(
        username=user_charlie,
        password="PasswordYangSalah!",
        face_image_input=face_charlie,
        custom_dongle_paths=[test_dongle_dir]
    )
    print(f"  * Skenario Password Salah        : {wrong_pwd_ok} -> {wrong_pwd_msg}")
    assert wrong_pwd_ok is False, "GAGAL: Password salah harus digagalkan."
    print("  [PASSED] Akses diblokir saat password salah.")
    
    # Skenario C: Wajah salah -> GAGAL
    wrong_face_ok, wrong_face_msg, _ = authenticate_user(
        username=user_charlie,
        password=pwd_charlie,
        face_image_input=face_bob_imposter,
        custom_dongle_paths=[test_dongle_dir]
    )
    print(f"  * Skenario Wajah Tidak Cocok     : {wrong_face_ok} -> {wrong_face_msg}")
    assert wrong_face_ok is False, "GAGAL: Wajah tidak cocok harus digagalkan."
    print("  [PASSED] Akses diblokir saat biometrik tidak cocok.")
    
    # Skenario D: Dongle dicabut / hilang -> GAGAL
    empty_path = DATA_DIR / "empty_slot"
    empty_path.mkdir(exist_ok=True)
    no_dongle_ok, no_dongle_msg, _ = authenticate_user(
        username=user_charlie,
        password=pwd_charlie,
        face_image_input=face_charlie,
        custom_dongle_paths=[empty_path]
    )
    # Hapus file kunci sementara dari virtual dongle agar pencarian gagal
    dongle_file = test_dongle_dir / DONGLE_KEY_FILENAME
    dongle_backup = test_dongle_dir / (DONGLE_KEY_FILENAME + ".bak")
    shutil.move(str(dongle_file), str(dongle_backup))
    
    no_dongle_ok, no_dongle_msg, _ = authenticate_user(
        username=user_charlie,
        password=pwd_charlie,
        face_image_input=face_charlie,
        custom_dongle_paths=[empty_path]
    )
    print(f"  * Skenario Dongle Dicabut        : {no_dongle_ok} -> {no_dongle_msg}")
    assert no_dongle_ok is False, "GAGAL: Ketiadaan dongle harus memblokir akses."
    print("  [PASSED] Akses diblokir saat dongle USB tidak terpasang.")
    
    # Kembalikan file backup
    shutil.move(str(dongle_backup), str(dongle_file))
    
    print("\n" + "=" * 75)
    print(" SELURUH PENGUJIAN TAHAP 2 BERHASIL 100%! SISTEM OTENTIKASI SIAP DIGUNAKAN.")
    print("=" * 75)


if __name__ == "__main__":
    run_tests()

