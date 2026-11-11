"""
==============================================================================
MODUL: AUTH MANAGER (ORCHESTRATOR 3-FACTOR AUTHENTICATION)
==============================================================================
Deskripsi:
Modul sentral yang menggabungkan ketiga faktor otentikasi:
1. Sesuatu yang dimiliki (Something you have): Hardware Dongle USB (HMAC + AES-256)
2. Sesuatu yang melekat (Something you are): Biometrik Wajah OpenCV
3. Sesuatu yang diketahui (Something you know): Password Master PBKDF2-HMAC-SHA256

Jika salah satu faktor gagal, akses ke aplikasi Secure Messenger DITOLAK total.
==============================================================================
"""

import json
import re
from pathlib import Path
from config.settings import DATA_DIR
from modules.auth.hasher import hash_password, verify_password
from modules.auth.dongle import verify_dongle, generate_dongle_key, get_removable_drives
from modules.auth.biometric import register_reference_face, verify_face

# File penyimpanan kredensial akun lokal (sebelum migrasi penuh ke SQLite di Tahap 4)
USER_REGISTRY_FILE = DATA_DIR / "users_auth_registry.json"


def _load_user_registry() -> dict:
    if not USER_REGISTRY_FILE.exists():
        return {}
    try:
        with open(USER_REGISTRY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_user_registry(registry: dict) -> None:
    with open(USER_REGISTRY_FILE, "w", encoding="utf-8") as f:
        json.dump(registry, f, indent=4)


def register_user(
    username: str,
    password: str,
    face_image_input,
    dongle_target_path: Path,
    db=None,
    dongle_per_user_folder: bool = False
) -> tuple[bool, str, dict | None]:
    """
    Mendaftarkan pengguna baru dengan 3 faktor keamanan sekaligus.
    
    Args:
        username (str): Nama pengguna unik.
        password (str): Password master.
        face_image_input: Citra wajah untuk foto rujukan.
        dongle_target_path (Path): Path drive USB atau folder tempat membuat file kunci dongle.
        
    Returns:
        tuple[bool, str, dict | None]: Status berhasil, pesan deskriptif, info registrasi.
    """
    clean_username = username.strip().lower()
    if not clean_username:
        return False, "Username tidak boleh kosong.", None
        
    # Validasi format karakter username agar aman pada sistem berkas Windows/Linux
    if not re.match(r"^[a-zA-Z0-9_\-\.]{3,32}$", clean_username):
        return (
            False,
            "Username tidak valid! Karakter '*', '?', ':', '/', '\\', dll. tidak diizinkan. "
            "Gunakan hanya huruf, angka, garis bawah (_), atau tanda hubung (-). Minimal 3 karakter.",
            None
        )
        
    if db is not None:
        if db.get_user(clean_username) is not None:
            return False, f"Pengguna dengan username '{clean_username}' sudah terdaftar.", None
    else:
        registry = _load_user_registry()
        if clean_username in registry:
            return False, f"Pengguna dengan username '{clean_username}' sudah terdaftar.", None
        
    # 1. Daftarkan Biometrik Wajah
    bio_success, bio_msg, ref_face_path = register_reference_face(clean_username, face_image_input)
    if not bio_success:
        return False, f"Registrasi dibatalkan karena biometrik gagal: {bio_msg}", None
        
    # 2. Buat Kunci Dongle USB
    try:
        key_path = generate_dongle_key(dongle_target_path, clean_username, per_user_folder=dongle_per_user_folder)
    except Exception as e:
        # Rollback foto jika dongle gagal dibuat
        if ref_face_path and ref_face_path.exists():
            ref_face_path.unlink()
        return False, f"Gagal membuat file kunci dongle pada '{dongle_target_path}': {str(e)}", None
        
    # 3. Hash Password dengan PBKDF2-HMAC-SHA256 + Salt
    pwd_hash_hex, salt_hex = hash_password(password)
    
    # 4. Simpan ke Registry dan Basis Data SQLite Terenkripsi
    user_record = {
        "username": clean_username,
        "password_hash": pwd_hash_hex,
        "salt": salt_hex,
        "reference_face_path": str(ref_face_path),
        "dongle_key_path": str(key_path)
    }
    registry = _load_user_registry()
    registry[clean_username] = user_record
    _save_user_registry(registry)
    
    try:
        if db is None:
            from modules.database.secure_db import SecureDatabase
            db = SecureDatabase()
        db.save_user(
            username=clean_username,
            password_hash=pwd_hash_hex,
            salt=salt_hex,
            ref_face_path=str(ref_face_path),
            dongle_key_path=str(key_path)
        )
    except Exception:
        pass
    
    return True, f"Pengguna '{clean_username}' berhasil didaftarkan dengan 3 faktor keamanan lengkap.", user_record


def authenticate_user(
    username: str,
    password: str,
    face_image_input,
    custom_dongle_paths: list[Path] = None,
    db=None
) -> tuple[bool, str, dict]:
    """
    Menjalankan proses otentikasi login 3-Faktor secara berurutan:
    1. Validasi Fisik Dongle USB
    2. Validasi Biometrik Wajah
    3. Validasi Hash Password PBKDF2
    
    Returns:
        tuple[bool, str, dict]: (Status Lolos, Pesan Hasil, Log Rincian Faktor)
    """
    clean_username = username.strip().lower()
    audit_report = {
        "username": clean_username,
        "dongle_status": False,
        "biometric_status": False,
        "password_status": False,
        "details": {}
    }
    
    user_data = None
    try:
        if db is None:
            from modules.database.secure_db import SecureDatabase
            db = SecureDatabase()
        user_data = db.get_user(clean_username)
    except Exception:
        pass
        
    if not user_data:
        registry = _load_user_registry()
        user_data = registry.get(clean_username)
        
    if not user_data:
        return False, f"Pengguna '{clean_username}' tidak ditemukan dalam database.", audit_report
    
    # =========================================================================
    # FAKTOR 1: VERIFIKASI DONGLE USB
    # =========================================================================
    dongle_ok, dongle_msg, dongle_payload = verify_dongle(
        username=clean_username,
        custom_search_paths=custom_dongle_paths,
        restrict_to_custom_paths=bool(custom_dongle_paths)
    )
    audit_report["dongle_status"] = dongle_ok
    audit_report["details"]["dongle"] = dongle_msg
    if not dongle_ok:
        return False, f"[FAKTOR 1 DITOLAK] {dongle_msg}", audit_report
        
    # =========================================================================
    # FAKTOR 2: VERIFIKASI BIOMETRIK WAJAH (OPENCV)
    # =========================================================================
    ref_face_path = user_data.get("reference_face_path")
    bio_ok, bio_msg, bio_score = verify_face(
        username=clean_username,
        live_image_input=face_image_input,
        stored_face_path=ref_face_path
    )
    audit_report["biometric_status"] = bio_ok
    audit_report["details"]["biometric"] = {
        "message": bio_msg,
        "similarity_score": bio_score
    }
    if not bio_ok:
        return False, f"[FAKTOR 2 DITOLAK] {bio_msg}", audit_report
        
    # =========================================================================
    # FAKTOR 3: VERIFIKASI PASSWORD (PBKDF2-HMAC-SHA256)
    # =========================================================================
    pwd_ok = verify_password(password, user_data["salt"], user_data["password_hash"])
    audit_report["password_status"] = pwd_ok
    audit_report["details"]["password"] = "Password valid" if pwd_ok else "Password salah"
    if not pwd_ok:
        return False, "[FAKTOR 3 DITOLAK] Kata sandi yang dimasukkan salah.", audit_report
        
    # JIKA SEMUA 3 FAKTOR LOLOS
    return True, f"OTENTIKASI SUKSES: Selamat datang, '{clean_username}'!", audit_report


def delete_user_account(username: str) -> bool:
    """Menghapus profil pengguna dari registry, basis data, dan berkas foto rujukan."""
    clean_username = username.strip().lower()
    registry = _load_user_registry()
    user_rec = registry.pop(clean_username, None)
    _save_user_registry(registry)
    
    if user_rec and "reference_face_path" in user_rec:
        p = Path(user_rec["reference_face_path"])
        if p.exists():
            try:
                p.unlink()
            except Exception:
                pass
                
    try:
        from modules.database.secure_db import SecureDatabase
        db = SecureDatabase()
        db.delete_user(clean_username)
    except Exception:
        pass
        
    return True

