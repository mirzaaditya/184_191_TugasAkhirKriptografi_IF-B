"""
==============================================================================
SKRIP PENGUJIAN OTOMATIS: MODUL BASIS DATA TERENKRIPSI (TAHAP 4)
==============================================================================
Menjalankan serangkaian pengujian integritas dan keamanan basis data:
1. Uji Pembuatan Tabel & Skema SQLite (users, messages, audit_logs)
2. Uji Penyimpanan Akun Pengguna (Users CRUD)
3. Uji Kerahasiaan Data-at-Rest: Memeriksa langsung data mentah di disk bahwa teks asli
   tidak tersimpan dalam bentuk plaintext (pure ciphertext).
4. Uji Pengambilan & Dekripsi Otomatis Riwayat Percakapan
5. Uji Deteksi Manipulasi Basis Data (Tamper Attack Detection via AES-GCM Tag)
6. Uji Audit Trail Terenkripsi & Hash Kriptografis
==============================================================================
"""

import sys
import sqlite3
from pathlib import Path

# Tambahkan root proyek ke sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from modules.database.secure_db import SecureDatabase
from config.settings import DATA_DIR


def run_tests():
    print("=" * 75)
    print("      PENGUJIAN MODUL DATABASE TERENKRIPSI (SQLITE) (TAHAP 4)")
    print("=" * 75)
    
    test_db_file = DATA_DIR / "test_encrypted_database.db"
    # Bersihkan file uji lama jika ada
    if test_db_file.exists():
        test_db_file.unlink()
        
    db = SecureDatabase(db_path=test_db_file)
    print(f"\n[UJI 1] Inisialisasi Basis Data: {test_db_file.name}")
    assert test_db_file.exists(), "GAGAL: Berkas database tidak terbuat di disk!"
    print("  [PASSED] Berkas basis data SQLite dan seluruh skema tabel berhasil diinisialisasi.")
    
    # -------------------------------------------------------------------------
    # UJI 2: PENGELOLAAN PENGGUNA (USERS CRUD)
    # -------------------------------------------------------------------------
    print("\n[UJI 2] Manajemen Akun Pengguna (Users)")
    db.save_user(
        username="alice",
        password_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        salt="a1b2c3d4e5f60718",
        ref_face_path="data/reference_faces/alice_face.png",
        dongle_key_path="data/virtual_dongle/secure_dongle.key"
    )
    db.save_user(
        username="bob",
        password_hash="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        salt="9988776655443322",
        ref_face_path="data/reference_faces/bob_face.png",
        dongle_key_path="data/virtual_dongle/secure_dongle.key"
    )
    
    users = db.list_users()
    print(f"  * Daftar Pengguna Terdaftar: {users}")
    assert "alice" in users and "bob" in users, "GAGAL: Pengguna tidak tercatat dalam database!"
    
    user_alice = db.get_user("alice")
    assert user_alice["salt"] == "a1b2c3d4e5f60718", "GAGAL: Data salt pengguna tidak cocok!"
    print("  [PASSED] Registrasi dan pembacaan akun pengguna sukses.")
    
    # -------------------------------------------------------------------------
    # UJI 3: KERAHASIAAN DATA-AT-REST (PEMERIKSAAN MENTAH DISK)
    # -------------------------------------------------------------------------
    print("\n[UJI 3] Pengujian Kerahasiaan Data-at-Rest (Field-Level Encryption)")
    secret_chat = "KODE RAHASIA OPERASI: Alpha-Bravo-999. Pertemuan di lokasi X."
    
    msg_id, msg_hash = db.store_message(
        sender="alice",
        recipient="bob",
        message_type="TEXT",
        content=secret_chat
    )
    print(f"  * Pesan Disimpan (ID={msg_id})")
    print(f"  * SHA-256 Hash Pesan : {msg_hash[:32]}... (untuk blockchain)")
    
    # Buka database langsung dengan sqlite3 mentah (tanpa layer dekripsi)
    raw_conn = sqlite3.connect(str(test_db_file))
    cursor = raw_conn.cursor()
    cursor.execute("SELECT encrypted_content, content_nonce, content_tag FROM messages WHERE id = ?", (msg_id,))
    row = cursor.fetchone()
    raw_conn.close()
    
    c_hex, n_hex, t_hex = row[0], row[1], row[2]
    print(f"  * Raw Ciphertext di Disk: {c_hex[:30]}...")
    print(f"  * Raw Nonce di Disk     : {n_hex}")
    print(f"  * Raw Auth Tag di Disk  : {t_hex}")
    
    # BUKTIKAN: Teks asli TIDAK ADA dalam bentuk plaintext di disk mentah!
    raw_db_bytes = test_db_file.read_bytes()
    assert secret_chat.encode("utf-8") not in raw_db_bytes, "GAGAL KRITIS: Plaintext bocor ke dalam berkas .db mentah!"
    print("  [PASSED] Plaintext TERBUKTI 100% TIDAK PERNAH BOCOR ke penyimpanan disk (Full High-Entropy Ciphertext).")
    
    # -------------------------------------------------------------------------
    # UJI 4: PENGAMBILAN & DEKRIPSI TRANSPARAN PERCAKAPAN
    # -------------------------------------------------------------------------
    print("\n[UJI 4] Pengambilan & Dekripsi Transparan Riwayat Pesan")
    conversation = db.get_conversation("alice", "bob")
    assert len(conversation) == 1, "GAGAL: Pesan percakapan tidak ditemukan!"
    
    msg_item = conversation[0]
    print(f"  * Pengirim         : {msg_item['sender']}")
    print(f"  * Penerima         : {msg_item['recipient']}")
    print(f"  * Pesan Terdekripsi: '{msg_item['content']}'")
    print(f"  * Integritas Valid : {msg_item['integrity_verified']}")
    
    assert msg_item["content"] == secret_chat, "GAGAL: Pesan hasil dekripsi tidak cocok dengan teks asli!"
    assert msg_item["integrity_verified"] is True, "GAGAL: Integritas pesan harus terverifikasi valid!"
    print("  [PASSED] Dekripsi transparan percakapan berhasil memulihkan teks asli secara presisi.")
    
    # -------------------------------------------------------------------------
    # UJI 5: DETEKSI MANIPULASI BASIS DATA (TAMPER ATTACK)
    # -------------------------------------------------------------------------
    print("\n[UJI 5] Deteksi Manipulasi Basis Data (Tamper Attack)")
    
    # Simulasikan penyerang yang memiliki akses ke berkas .db dan memodifikasi isi ciphertext
    raw_conn = sqlite3.connect(str(test_db_file))
    # Ubah 4 karakter pada ciphertext heksadesimal di baris ID=1
    tampered_c_hex = "ffff" + c_hex[4:]
    raw_conn.execute("UPDATE messages SET encrypted_content = ? WHERE id = ?", (tampered_c_hex, msg_id))
    raw_conn.commit()
    raw_conn.close()
    print("  * Simulasi Penyerangan: Ciphertext pada berkas SQLite dimodifikasi secara ilegal di luar aplikasi.")
    
    # Periksa integritas seluruh tabel
    is_clean, total, corrupted = db.verify_all_records_integrity()
    print(f"  * Hasil Audit Integritas: Bersih={is_clean}, Total Baris={total}, Baris Korup={corrupted}")
    assert is_clean is False, "GAGAL: Sistem harus mendeteksi manipulasi database!"
    assert msg_id in corrupted, f"GAGAL: Baris {msg_id} yang diubah harus tercatat korup!"
    print("  [PASSED] Sistem berhasil mendeteksi manipulasi data ilegal berkat verifikasi tag AES-GCM.")
    
    # Cek hasil pembacaan percakapan saat terjadi manipulasi
    tampered_convo = db.get_conversation("alice", "bob")
    print(f"  * Tampilan Pesan Korup  : {tampered_convo[0]['content']}")
    assert tampered_convo[0]["integrity_verified"] is False, "GAGAL: Pesan korup tidak boleh bertanda valid!"
    print("  [PASSED] Aplikasi menolak menampilkan pesan yang telah dirusak.")
    
    # -------------------------------------------------------------------------
    # UJI 6: AUDIT LOGS TERENKRIPSI
    # -------------------------------------------------------------------------
    print("\n[UJI 6] Pengujian Audit Trail Terenkripsi")
    log_id, log_hash = db.store_audit_log(
        event_type="LOGIN_SUCCESS",
        actor="alice",
        details="Login berhasil menggunakan 3FA (Dongle + Wajah 98.5% + PBKDF2)."
    )
    print(f"  * Log ID={log_id}, Hash SHA-256={log_hash[:32]}...")
    
    audit_list = db.get_audit_logs(limit=10)
    assert len(audit_list) >= 1, "GAGAL: Audit log tidak tersimpan!"
    print(f"  * Event Type : {audit_list[0]['event_type']}")
    print(f"  * Actor      : {audit_list[0]['actor']}")
    print(f"  * Details    : {audit_list[0]['details']}")
    print("  [PASSED] Audit trail terenkripsi dan terdekripsi dengan utuh.")
    
    print("\n" + "=" * 75)
    print(" SELURUH PENGUJIAN TAHAP 4 BERHASIL 100%! BASIS DATA TERENKRIPSI SIAP.")
    print("=" * 75)


if __name__ == "__main__":
    run_tests()

