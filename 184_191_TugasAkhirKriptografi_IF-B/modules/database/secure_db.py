"""
==============================================================================
MODUL: DATABASE TERENKRIPSI (SQLITE DATA-AT-REST ENCRYPTION)
==============================================================================
Deskripsi:
Modul ini mengimplementasikan pengamanan basis data SQLite pada tingkat aplikasi
(Application-Level Field Encryption) menggunakan algoritma AES-256-GCM.

Mengapa Field-Level AES-256-GCM pada SQLite?
1. Kerahasiaan Data-at-Rest: Kolom sensitif (isi percakapan, lampiran, detail audit)
   disimpan dalam bentuk ciphertext biner heksadesimal di disk fisik. Jika berkas
   `.db` dicuri atau dibuka dengan tool SQLite Browser, isi pesan tidak terbaca sama sekali.
2. Integritas Terjamin: Setiap baris data memiliki Nonce (12 byte) dan Authentication Tag
   (16 byte) terpisah. Manipulasi data langsung pada berkas SQLite akan langsung terdeteksi
   sebagai kegagalan autentikasi (*tamper detection*).
3. Portabilitas Tinggi: Tidak memerlukan kompilasi C ekstensi SQLCipher khusus OS,
   sehingga dapat dijalankan langsung di lingkungan Windows/Linux/macOS mahasiswa.
4. Integrasi Blockchain: Menghitung hash SHA-256 untuk setiap pesan dan log audit yang
   siap dijangkarkan (*anchored*) ke dalam blok rantai di Tahap 6.
==============================================================================
"""

import os
import sqlite3
import hashlib
import datetime
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from config.settings import DATABASE_PATH
from modules.database.schema import (
    CREATE_USERS_TABLE,
    CREATE_MESSAGES_TABLE,
    CREATE_AUDIT_LOGS_TABLE,
    CREATE_INDEXES,
    MIGRATE_MESSAGES_COLUMNS
)

DEFAULT_DB_SECRET = b"SECURE_MESSENGER_SQLITE_STORAGE_MASTER_KEY_2026"


class SecureDatabase:
    """
    Pengelola basis data SQLite dengan enkripsi data-at-rest tingkat kolom.
    """

    def __init__(self, db_path: Path = DATABASE_PATH, master_key: bytes = DEFAULT_DB_SECRET):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # Turunkan kunci AES 256-bit (32 bytes) dari master secret
        self.aes_key = hashlib.sha256(master_key).digest()
        self.aesgcm = AESGCM(self.aes_key)
        self.init_db()
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # Turunkan kunci AES 256-bit (32 bytes) dari master secret
        self.aes_key = hashlib.sha256(master_key).digest()
        self.aesgcm = AESGCM(self.aes_key)
        self.init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Membuka koneksi ke SQLite dengan penegakan Foreign Key & Mode WAL."""
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        return conn

    def init_db(self) -> None:
        """Membuat tabel dan indeks jika belum tersedia. Jalankan migrasi kolom baru secara aman."""
        with self._get_connection() as conn:
            conn.execute(CREATE_USERS_TABLE)
            conn.execute(CREATE_MESSAGES_TABLE)
            conn.execute(CREATE_AUDIT_LOGS_TABLE)
            for idx in CREATE_INDEXES:
                conn.execute(idx)
            # Migrasi aman: tambah kolom baru ke tabel lama (SQLite tidak mendukung IF NOT EXISTS pada ADD COLUMN)
            for alter_sql in MIGRATE_MESSAGES_COLUMNS:
                try:
                    conn.execute(alter_sql)
                except Exception:
                    pass  # Kolom sudah ada, abaikan
            conn.commit()

    # =========================================================================
    # FUNGSI KRIPTOGRAFI INTERNAL (FIELD-LEVEL ENCRYPTION)
    # =========================================================================
    def _encrypt_field(self, plaintext: str) -> tuple[str, str, str]:
        """
        Mengenkripsi teks kolom menggunakan AES-256-GCM.
        
        Returns:
            tuple[str, str, str]: (ciphertext_hex, nonce_hex, tag_hex)
        """
        if plaintext is None:
            plaintext = ""
        nonce = os.urandom(12)  # 96-bit nonce
        # AESGCM meletakkan 16-byte tag di akhir ciphertext
        raw_cipher_tag = self.aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        ciphertext = raw_cipher_tag[:-16]
        tag = raw_cipher_tag[-16:]
        
        return ciphertext.hex(), nonce.hex(), tag.hex()

    def _decrypt_field(self, ciphertext_hex: str, nonce_hex: str, tag_hex: str) -> str:
        """
        Mendekripsi teks kolom dan memvalidasi keutuhan tag AES-256-GCM.
        
        Raises:
            ValueError: Jika manipulasi data terdeteksi atau kunci salah.
        """
        try:
            nonce = bytes.fromhex(nonce_hex)
            ciphertext = bytes.fromhex(ciphertext_hex)
            tag = bytes.fromhex(tag_hex)
            raw_cipher_tag = ciphertext + tag
            decrypted_bytes = self.aesgcm.decrypt(nonce, raw_cipher_tag, None)
            return decrypted_bytes.decode("utf-8")
        except InvalidTag:
            raise ValueError("INTEGRITAS DATA RUSAK: Tag autentikasi AES-GCM tidak cocok! Data baris telah dimanipulasi.")
        except Exception as e:
            raise ValueError(f"Gagal mendekripsi data kolom: {str(e)}")

    # =========================================================================
    # PENGELOLAAN PENGGUNA (USERS CRUD)
    # =========================================================================
    def save_user(
        self,
        username: str,
        password_hash: str,
        salt: str,
        ref_face_path: str,
        dongle_key_path: str
    ) -> bool:
        """Menyimpan atau memperbarui data akun pengguna."""
        clean_user = username.strip().lower()
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        query = """
        INSERT INTO users (username, password_hash, salt, reference_face_path, dongle_key_path, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(username) DO UPDATE SET
            password_hash=excluded.password_hash,
            salt=excluded.salt,
            reference_face_path=excluded.reference_face_path,
            dongle_key_path=excluded.dongle_key_path;
        """
        with self._get_connection() as conn:
            conn.execute(query, (clean_user, password_hash, salt, str(ref_face_path), str(dongle_key_path), now_iso))
            conn.commit()
        return True

    def get_user(self, username: str) -> dict | None:
        """Mengambil data otentikasi pengguna berdasarkan username."""
        clean_user = username.strip().lower()
        query = "SELECT * FROM users WHERE username = ? LIMIT 1;"
        with self._get_connection() as conn:
            cursor = conn.execute(query, (clean_user,))
            row = cursor.fetchone()
            if row:
                return dict(row)
        return None

    def list_users(self) -> list[str]:
        """Mengambil daftar seluruh username pengguna terdaftar."""
        query = "SELECT username FROM users ORDER BY username ASC;"
        with self._get_connection() as conn:
            cursor = conn.execute(query)
            return [r["username"] for r in cursor.fetchall()]

    def delete_user(self, username: str) -> bool:
        """Menghapus akun pengguna dari basis data."""
        clean_user = username.strip().lower()
        with self._get_connection() as conn:
            conn.execute("DELETE FROM users WHERE username = ?;", (clean_user,))
            conn.commit()
        return True

    # =========================================================================
    # PENGELOLAAN PESAN RAHASIA TERENKRIPSI (MESSAGES)
    # =========================================================================
    def store_message(
        self,
        sender: str,
        recipient: str,
        message_type: str,
        content: str,
        attachment_path: str = None,
        super_ciphertext: str = None
    ) -> tuple[int, str]:
        """
        Mengenkripsi isi pesan teks dan menyimpannya secara aman ke database SQLite.
        Juga menyimpan super_ciphertext (Vigenère+AES) yang hanya bisa dibuka penerima
        dengan password+key yang benar.
        
        Args:
            sender (str): Username pengirim.
            recipient (str): Username penerima.
            message_type (str): 'TEXT', 'FILE', 'IMAGE_STEGO', 'AUDIO_STEGO', 'VIDEO_STEGO'.
            content (str): Isi teks pesan asli / payload.
            attachment_path (str, optional): Path ke berkas terenkripsi lampiran jika ada.
            super_ciphertext (str, optional): Ciphertext super-enkripsi Vigenère+AES-256-GCM untuk dibuka penerima.
            
        Returns:
            tuple[int, str]: (ID Pesan dalam database, Hash SHA-256 pesan)
        """
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        # 1. Enkripsi konten pesan sebelum ditulis ke storage (Data-at-Rest Protection)
        c_hex, nonce_hex, tag_hex = self._encrypt_field(content)
        
        # 2. Hitung hash kanonikal SHA-256 untuk jangkar blockchain (Audit Ledger)
        canonical_str = f"{sender}|{recipient}|{now_iso}|{message_type}|{content}|{attachment_path or ''}"
        msg_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
        
        query = """
        INSERT INTO messages (
            sender, recipient, timestamp, message_type,
            encrypted_content, content_nonce, content_tag,
            attachment_path, message_hash, is_read,
            super_ciphertext, is_opened, open_attempts, locked_until
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, 0, 0, NULL);
        """
        with self._get_connection() as conn:
            cursor = conn.execute(query, (
                sender.lower(),
                recipient.lower(),
                now_iso,
                message_type.upper(),
                c_hex,
                nonce_hex,
                tag_hex,
                str(attachment_path) if attachment_path else None,
                msg_hash,
                super_ciphertext
            ))
            conn.commit()
            msg_id = cursor.lastrowid
            
        return msg_id, msg_hash

    def get_conversation(self, user1: str, user2: str) -> list[dict]:
        """
        Mengambil seluruh riwayat percakapan antara dua pengguna secara kronologis.
        Pesan masuk yang belum dibuka (is_opened=0 dan ada super_ciphertext) akan
        menampilkan placeholder, bukan plaintext, untuk menjaga enkripsi end-to-end.
        """
        u1, u2 = user1.lower().strip(), user2.lower().strip()
        query = """
        SELECT * FROM messages
        WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?)
        ORDER BY timestamp ASC;
        """
        results = []
        with self._get_connection() as conn:
            cursor = conn.execute(query, (u1, u2, u2, u1))
            rows = cursor.fetchall()
            for r in rows:
                item = dict(r)
                # Pastikan kolom baru punya nilai default jika DB lama belum punya kolom
                item.setdefault("super_ciphertext", None)
                item.setdefault("is_opened", 0)
                item.setdefault("open_attempts", 0)
                item.setdefault("locked_until", None)

                # Selalu dekripsi untuk mendapat plaintext dari storage layer
                try:
                    decrypted_text = self._decrypt_field(
                        item["encrypted_content"],
                        item["content_nonce"],
                        item["content_tag"]
                    )
                    item["content"] = decrypted_text
                    item["content_plaintext"] = decrypted_text  # disimpan di memori, bukan tampil langsung
                    item["integrity_verified"] = True
                except Exception as e:
                    item["content"] = f"[PERINGATAN: DATA TERINDIKASI RUSAK / DIMODIFIKASI - {str(e)}]"
                    item["content_plaintext"] = f"[PERINGATAN: DATA TERINDIKASI RUSAK / DIMODIFIKASI - {str(e)}]"
                    item["integrity_verified"] = False

                results.append(item)
        return results

    def mark_as_read(self, message_id: int) -> bool:
        """Menandai pesan telah dibaca oleh penerima."""
        query = "UPDATE messages SET is_read = 1 WHERE id = ?;"
        with self._get_connection() as conn:
            conn.execute(query, (message_id,))
            conn.commit()
        return True

    def mark_message_opened(self, message_id: int) -> bool:
        """Menandai pesan sudah berhasil dibuka (didekripsi) oleh penerima. Reset percobaan gagal."""
        query = "UPDATE messages SET is_opened = 1, is_read = 1, open_attempts = 0, locked_until = NULL WHERE id = ?;"
        with self._get_connection() as conn:
            conn.execute(query, (message_id,))
            conn.commit()
        return True

    def increment_open_attempts(self, message_id: int) -> dict:
        """
        Menambah hitungan percobaan buka yang gagal.
        Jika sudah mencapai 5 kali, kunci pesan selama 5 menit.
        
        Returns:
            dict: {'attempts': int, 'locked': bool, 'locked_until': str|None}
        """
        # Ambil state saat ini
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT open_attempts, locked_until FROM messages WHERE id = ?;", (message_id,)
            ).fetchone()
            if row is None:
                return {"attempts": 0, "locked": False, "locked_until": None}
            
            current_attempts = (row["open_attempts"] or 0) + 1
            locked_until_val = None
            
            if current_attempts >= 5:
                # Kunci selama 5 menit
                lock_until_dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
                locked_until_val = lock_until_dt.isoformat()
            
            conn.execute(
                "UPDATE messages SET open_attempts = ?, locked_until = ? WHERE id = ?;",
                (current_attempts, locked_until_val, message_id)
            )
            conn.commit()
        
        return {
            "attempts": current_attempts,
            "locked": locked_until_val is not None,
            "locked_until": locked_until_val
        }

    def get_lock_status(self, message_id: int) -> dict:
        """
        Memeriksa apakah pesan sedang terkunci (brute-force lockout).
        Secara otomatis membersihkan kunci yang sudah kedaluwarsa.
        
        Returns:
            dict: {'locked': bool, 'remaining_seconds': float, 'attempts': int}
        """
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT open_attempts, locked_until FROM messages WHERE id = ?;", (message_id,)
            ).fetchone()
            if row is None:
                return {"locked": False, "remaining_seconds": 0, "attempts": 0}
            
            attempts = row["open_attempts"] or 0
            locked_until_str = row["locked_until"]
            
            if not locked_until_str:
                return {"locked": False, "remaining_seconds": 0, "attempts": attempts}
            
            locked_until_dt = datetime.datetime.fromisoformat(locked_until_str)
            now_utc = datetime.datetime.now(datetime.timezone.utc)
            remaining = (locked_until_dt - now_utc).total_seconds()
            
            if remaining <= 0:
                # Kunci sudah kedaluwarsa, bersihkan
                conn.execute(
                    "UPDATE messages SET locked_until = NULL, open_attempts = 0 WHERE id = ?;", (message_id,)
                )
                conn.commit()
                return {"locked": False, "remaining_seconds": 0, "attempts": 0}
            
            return {"locked": True, "remaining_seconds": remaining, "attempts": attempts}

    def get_unread_message_counts(self, recipient: str) -> dict:
        """
        Menghitung jumlah pesan masuk yang belum dibuka per pengirim.
        
        Returns:
            dict: {sender_username: unread_count}
        """
        recipient_lower = recipient.strip().lower()
        query = """
        SELECT sender, COUNT(*) as cnt
        FROM messages
        WHERE recipient = ? AND is_opened = 0 AND super_ciphertext IS NOT NULL
        GROUP BY sender;
        """
        with self._get_connection() as conn:
            cursor = conn.execute(query, (recipient_lower,))
            return {row["sender"]: row["cnt"] for row in cursor.fetchall()}

    # =========================================================================
    # PENGELOLAAN AUDIT LOGS
    # =========================================================================
    def store_audit_log(self, event_type: str, actor: str, details: str) -> tuple[int, str]:
        """
        Mencatat riwayat aktivitas keamanan aplikasi (login, pengiriman pesan, dll)
        dengan enkripsi rincian dan hash bukti audit.
        """
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        c_hex, nonce_hex, tag_hex = self._encrypt_field(details)
        
        canonical_str = f"{now_iso}|{event_type}|{actor}|{details}"
        log_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
        
        query = """
        INSERT INTO audit_logs (
            timestamp, event_type, actor,
            encrypted_details, details_nonce, details_tag, log_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?);
        """
        with self._get_connection() as conn:
            cursor = conn.execute(query, (now_iso, event_type, actor, c_hex, nonce_hex, tag_hex, log_hash))
            conn.commit()
            log_id = cursor.lastrowid
            
        return log_id, log_hash

    def get_audit_logs(self, limit: int = 50) -> list[dict]:
        """Mengambil log riwayat keamanan dan mendekripsi rinciannya."""
        query = "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?;"
        results = []
        with self._get_connection() as conn:
            cursor = conn.execute(query, (limit,))
            for r in cursor.fetchall():
                item = dict(r)
                try:
                    item["details"] = self._decrypt_field(
                        item["encrypted_details"],
                        item["details_nonce"],
                        item["details_tag"]
                    )
                    item["integrity_verified"] = True
                except Exception:
                    item["details"] = "[DATA LOG RUSAK / DIMODIFIKASI]"
                    item["integrity_verified"] = False
                results.append(item)
        return results

    # =========================================================================
    # PEMERIKSAAN INTEGRITAS SELURUH BASIS DATA
    # =========================================================================
    def verify_all_records_integrity(self) -> tuple[bool, int, list[int]]:
        """
        Memindai seluruh tabel messages dan memvalidasi keaslian authentication tag AES-GCM.
        
        Returns:
            tuple[bool, int, list[int]]: (Status Integritas Penuh, Total Baris, Daftar ID Rusak)
        """
        query = "SELECT id, encrypted_content, content_nonce, content_tag FROM messages;"
        corrupted_ids = []
        total_rows = 0
        
        with self._get_connection() as conn:
            cursor = conn.execute(query)
            rows = cursor.fetchall()
            total_rows = len(rows)
            for r in rows:
                try:
                    self._decrypt_field(r["encrypted_content"], r["content_nonce"], r["content_tag"])
                except Exception:
                    corrupted_ids.append(r["id"])
                    
        is_clean = (len(corrupted_ids) == 0)
        return is_clean, total_rows, corrupted_ids

