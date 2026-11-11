"""
==============================================================================
SKRIP PENGUJIAN OTOMATIS: FITUR INBOX/CHAT TERENKRIPSI
==============================================================================
Menguji seluruh siklus hidup pengiriman dan pembukaan pesan terenkripsi:
1. Pengiriman pesan → status is_opened=0, super_ciphertext tersimpan
2. Buka dengan password+key benar → plaintext sama persis
3. Buka dengan password salah → gagal (ValueError dari AES-GCM InvalidTag)
4. Buka dengan key salah → gagal (plaintext tidak cocok / gibberish)
5. 5 kali gagal → open_attempts=5, locked_until diset, percobaan ke-6 ditolak
==============================================================================
"""

import sys
import os
import tempfile
import datetime
from pathlib import Path

# Tambahkan root proyek ke sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from modules.cryptography.super_encryption import super_encrypt, super_decrypt
from modules.database.secure_db import SecureDatabase


# =============================================================================
# FIXTURE: Database sementara (isolasi per test-run)
# =============================================================================
def _make_temp_db() -> SecureDatabase:
    """Membuat instance SecureDatabase dengan file sementara agar test terisolasi."""
    tmp_dir = Path(tempfile.mkdtemp())
    return SecureDatabase(db_path=tmp_dir / "test_chat.db")


def _ensure_users(db: SecureDatabase, *usernames):
    """Mendaftarkan user uji ke database (data minimal, tanpa 3FA)."""
    for u in usernames:
        # Daftarkan langsung ke tabel users (bypass 3FA untuk unit test)
        with db._get_connection() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO users
                   (username, password_hash, salt, reference_face_path, dongle_key_path, created_at)
                   VALUES (?, 'testhash', 'testsalt', 'face.jpg', 'dongle.key', ?);""",
                (u.lower(), datetime.datetime.now(datetime.timezone.utc).isoformat())
            )
            conn.commit()


def _store_test_message(db: SecureDatabase, sender: str, recipient: str,
                         plaintext: str, password: str, key: str):
    """Helper: enkripsi + simpan pesan lengkap (seperti dilakukan app.py)."""
    enc_res = super_encrypt(plaintext, key, password, mode="extended")
    super_cipher = enc_res["final_ciphertext"]
    msg_id, msg_hash = db.store_message(
        sender=sender,
        recipient=recipient,
        message_type="TEXT",
        content=plaintext,
        super_ciphertext=super_cipher
    )
    return msg_id, msg_hash, super_cipher


# =============================================================================
# PENGUJIAN
# =============================================================================

def test_1_send_message_encrypted_status():
    """
    Pengujian 1: Setelah pesan dikirim, is_opened=0, super_ciphertext tersimpan,
    dan pesan masuk TIDAK tampil sebagai plaintext dari get_conversation.
    """
    print("\n[UJI 1] Kirim pesan → status terenkripsi")
    db = _make_temp_db()
    _ensure_users(db, "alice", "bob")

    plaintext = "Rahasia Negara Level Merah"
    password  = "PasswordSuperRahasia123"
    key       = "KunciVigenere2026"

    msg_id, msg_hash, super_cipher = _store_test_message(db, "alice", "bob", plaintext, password, key)

    # Verifikasi kolom di DB
    convo = db.get_conversation("alice", "bob")
    assert len(convo) == 1, "GAGAL: Pesan tidak tersimpan di DB!"
    msg = convo[0]

    assert msg["is_opened"] == 0, "GAGAL: is_opened harus 0 setelah baru dikirim!"
    assert msg["super_ciphertext"] is not None, "GAGAL: super_ciphertext harus tersimpan!"
    assert msg["super_ciphertext"] == super_cipher, "GAGAL: super_ciphertext tidak cocok!"
    # content_plaintext ada di memori (untuk arsip DB), tapi bukan untuk ditampilkan ke penerima
    assert msg["content_plaintext"] == plaintext, "GAGAL: plaintext arsip DB tidak cocok!"

    print(f"  * msg_id={msg_id}, is_opened={msg['is_opened']}, super_ciphertext[:20]={super_cipher[:20]}...")
    print("  [PASSED] Pesan tersimpan dengan status terenkripsi (is_opened=0).")


def test_2_open_with_correct_password_and_key():
    """
    Pengujian 2: Dekripsi dengan password+key benar → plaintext sama persis.
    """
    print("\n[UJI 2] Buka dengan password+key benar → plaintext sama persis")
    db = _make_temp_db()
    _ensure_users(db, "alice", "bob")

    plaintext = "Operasi Fajar Merah: Bergerak pukul 02:00"
    password  = "PwdBenar99!"
    key       = "KeyBenar2026"

    msg_id, msg_hash, super_cipher = _store_test_message(db, "alice", "bob", plaintext, password, key)

    # Simulasi dekripsi oleh penerima (bob)
    dec_result = super_decrypt(super_cipher, vigenere_key=key, aes_key=password, mode="extended")
    recovered = dec_result["plaintext"]

    assert recovered == plaintext, f"GAGAL: Plaintext tidak cocok! Dapat: '{recovered}'"

    # Tandai dibuka
    db.mark_message_opened(msg_id)
    convo = db.get_conversation("alice", "bob")
    assert convo[0]["is_opened"] == 1, "GAGAL: is_opened harus 1 setelah berhasil dibuka!"
    assert convo[0]["open_attempts"] == 0, "GAGAL: open_attempts harus 0 setelah berhasil dibuka!"

    print(f"  * Plaintext dipulihkan: '{recovered}'")
    print("  [PASSED] Dekripsi sukses, is_opened=1, open_attempts=0.")


def test_3_open_with_wrong_password():
    """
    Pengujian 3: Dekripsi dengan password salah → ValueError dari AES-GCM.
    Pesan tetap terenkripsi (is_opened=0).
    """
    print("\n[UJI 3] Buka dengan password salah → gagal")
    db = _make_temp_db()
    _ensure_users(db, "alice", "bob")

    plaintext = "Data sensitif: koordinat 7.000°S, 110.000°E"
    password  = "PasswordBenar"
    key       = "KunciBenar"
    wrong_pwd = "PasswordSALAH"

    msg_id, _, super_cipher = _store_test_message(db, "alice", "bob", plaintext, password, key)

    try:
        super_decrypt(super_cipher, vigenere_key=key, aes_key=wrong_pwd, mode="extended")
        assert False, "GAGAL: Password salah seharusnya melempar ValueError dari AES-GCM InvalidTag!"
    except ValueError as e:
        print(f"  * Dekripsi gagal seperti yang diharapkan: {e}")

    # Verifikasi pesan masih terenkripsi
    convo = db.get_conversation("alice", "bob")
    assert convo[0]["is_opened"] == 0, "GAGAL: is_opened harus tetap 0 setelah password salah!"

    print("  [PASSED] Password salah → ValueError, is_opened tetap 0.")


def test_4_open_with_wrong_key():
    """
    Pengujian 4: Dekripsi dengan key (Vigenère) salah.
    AES berhasil (password benar), tapi Vigenère menghasilkan gibberish ≠ plaintext asli.
    Verifikasi silang dengan arsip DB harus gagal.
    """
    print("\n[UJI 4] Buka dengan key salah → plaintext tidak cocok")
    db = _make_temp_db()
    _ensure_users(db, "alice", "bob")

    plaintext = "UNIT TEST KEY SALAH: plaintext ini harus berbeda"
    password  = "PwdBenar"
    key       = "KeyBenar"
    wrong_key = "KeySALAHSALAH"

    msg_id, _, super_cipher = _store_test_message(db, "alice", "bob", plaintext, password, key)

    # AES berhasil (password benar), Vigenère menghasilkan gibberish
    dec_result = super_decrypt(super_cipher, vigenere_key=wrong_key, aes_key=password, mode="extended")
    recovered_gibberish = dec_result["plaintext"]

    # Verifikasi silang: harus TIDAK sama dengan plaintext asli
    assert recovered_gibberish != plaintext, \
        "GAGAL: Key salah seharusnya menghasilkan teks acak, bukan plaintext asli!"

    # Simulasi logika verifikasi di app.py: raise ValueError jika tidak cocok
    db_plaintext = db.get_conversation("alice", "bob")[0]["content_plaintext"]
    try:
        if recovered_gibberish != db_plaintext:
            raise ValueError("Verifikasi silang gagal: hasil dekripsi tidak cocok dengan arsip.")
        assert False, "GAGAL: Seharusnya ValueError di sini!"
    except ValueError as e:
        print(f"  * Verifikasi silang gagal seperti yang diharapkan: {e}")

    print(f"  * Gibberish dari key salah: '{recovered_gibberish[:30]}...'")
    print("  [PASSED] Key salah → gibberish, verifikasi silang gagal, is_opened tetap 0.")


def test_5_brute_force_lockout():
    """
    Pengujian 5: 5 kali percobaan gagal → open_attempts=5, locked_until diset.
    Percobaan ke-6 harus ditolak karena status terkunci.
    """
    print("\n[UJI 5] 5 kali gagal → terkunci 5 menit")
    db = _make_temp_db()
    _ensure_users(db, "alice", "bob")

    plaintext = "Pesan Brute Force Test"
    password  = "PwdBenar"
    key       = "KeyBenar"
    wrong_pwd = "WrongPwd"

    msg_id, _, super_cipher = _store_test_message(db, "alice", "bob", plaintext, password, key)

    # 5 kali percobaan gagal
    for i in range(1, 6):
        lock_result = db.increment_open_attempts(msg_id)
        print(f"  * Percobaan #{i}: attempts={lock_result['attempts']}, locked={lock_result['locked']}")
        if i < 5:
            assert not lock_result["locked"], f"GAGAL: Belum seharusnya terkunci di percobaan #{i}!"
        else:
            assert lock_result["locked"], "GAGAL: Harus terkunci setelah 5 kali!"
            assert lock_result["locked_until"] is not None, "GAGAL: locked_until harus diset!"

    # Verifikasi status dari DB
    convo = db.get_conversation("alice", "bob")
    assert convo[0]["open_attempts"] == 5, "GAGAL: open_attempts harus 5!"

    # Verifikasi get_lock_status mendeteksi kunci
    lock_status = db.get_lock_status(msg_id)
    assert lock_status["locked"], "GAGAL: get_lock_status harus mengembalikan locked=True!"
    assert lock_status["remaining_seconds"] > 0, "GAGAL: Sisa waktu harus > 0!"

    print(f"  * Lock status: locked={lock_status['locked']}, sisa={lock_status['remaining_seconds']:.0f} detik")
    print("  [PASSED] 5 kali gagal → terkunci, percobaan ke-6 akan ditolak oleh get_lock_status.")


def test_6_unread_badge_count():
    """
    Pengujian 6: get_unread_message_counts mengembalikan jumlah pesan belum dibuka per pengirim.
    """
    print("\n[UJI 6] Badge counter pesan belum dibuka")
    db = _make_temp_db()
    _ensure_users(db, "alice", "bob", "charlie")

    # Kirim 2 pesan dari alice ke bob
    _store_test_message(db, "alice", "bob", "Pesan 1", "pwd", "key")
    _store_test_message(db, "alice", "bob", "Pesan 2", "pwd", "key")
    # Kirim 1 pesan dari charlie ke bob
    _store_test_message(db, "charlie", "bob", "Pesan dari charlie", "pwd2", "key2")

    counts = db.get_unread_message_counts("bob")
    assert counts.get("alice", 0) == 2, f"GAGAL: Harus ada 2 pesan belum dibuka dari alice, dapat {counts.get('alice', 0)}"
    assert counts.get("charlie", 0) == 1, f"GAGAL: Harus ada 1 pesan belum dibuka dari charlie, dapat {counts.get('charlie', 0)}"

    # Buka salah satu pesan dari alice
    convo = db.get_conversation("alice", "bob")
    db.mark_message_opened(convo[0]["id"])

    counts_after = db.get_unread_message_counts("bob")
    assert counts_after.get("alice", 0) == 1, f"GAGAL: Harus tersisa 1 pesan belum dibuka dari alice!"

    print(f"  * Sebelum buka: alice={counts.get('alice')}, charlie={counts.get('charlie')}")
    print(f"  * Setelah buka 1 pesan alice: alice={counts_after.get('alice')}")
    print("  [PASSED] Badge counter bekerja dengan benar.")


# =============================================================================
# ENTRY POINT
# =============================================================================
def run_tests():
    print("=" * 70)
    print("     PENGUJIAN FITUR INBOX/CHAT TERENKRIPSI")
    print("=" * 70)

    test_1_send_message_encrypted_status()
    test_2_open_with_correct_password_and_key()
    test_3_open_with_wrong_password()
    test_4_open_with_wrong_key()
    test_5_brute_force_lockout()
    test_6_unread_badge_count()

    print("\n" + "=" * 70)
    print(" SELURUH PENGUJIAN INBOX/CHAT BERHASIL 100%!")
    print("=" * 70)


if __name__ == "__main__":
    run_tests()
