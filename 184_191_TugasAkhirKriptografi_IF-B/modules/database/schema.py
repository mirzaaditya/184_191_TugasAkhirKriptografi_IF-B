"""
==============================================================================
SKEMA TABEL BASIS DATA (SQLITE DDL)
==============================================================================
Deskripsi:
Mendefinisikan skema tabel untuk sistem Secure Messenger:
1. `users`: Menyimpan kredensial otentikasi (hash password PBKDF2, salt, path biometrik & dongle).
2. `messages`: Menyimpan riwayat percakapan dengan payload terenkripsi AES-256-GCM.
3. `audit_logs`: Menyimpan jejak aktivitas keamanan terenkripsi dan hash SHA-256.
==============================================================================
"""

CREATE_USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    reference_face_path TEXT NOT NULL,
    dongle_key_path TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

CREATE_MESSAGES_TABLE = """
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    message_type TEXT NOT NULL,
    encrypted_content TEXT NOT NULL,
    content_nonce TEXT NOT NULL,
    content_tag TEXT NOT NULL,
    attachment_path TEXT,
    message_hash TEXT NOT NULL,
    is_read INTEGER DEFAULT 0,
    super_ciphertext TEXT DEFAULT NULL,
    is_opened INTEGER DEFAULT 0,
    open_attempts INTEGER DEFAULT 0,
    locked_until TEXT DEFAULT NULL,
    FOREIGN KEY (sender) REFERENCES users(username) ON DELETE CASCADE,
    FOREIGN KEY (recipient) REFERENCES users(username) ON DELETE CASCADE
);
"""

# Migrasi aman: tambah kolom baru ke tabel yang sudah ada (IF NOT EXISTS tidak berlaku untuk kolom di SQLite)
MIGRATE_MESSAGES_COLUMNS = [
    "ALTER TABLE messages ADD COLUMN super_ciphertext TEXT DEFAULT NULL;",
    "ALTER TABLE messages ADD COLUMN is_opened INTEGER DEFAULT 0;",
    "ALTER TABLE messages ADD COLUMN open_attempts INTEGER DEFAULT 0;",
    "ALTER TABLE messages ADD COLUMN locked_until TEXT DEFAULT NULL;",
]

CREATE_AUDIT_LOGS_TABLE = """
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    encrypted_details TEXT NOT NULL,
    details_nonce TEXT NOT NULL,
    details_tag TEXT NOT NULL,
    log_hash TEXT NOT NULL
);
"""

# Indeks untuk mempercepat pencarian percakapan antar dua pengguna dan log audit
CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_messages_users ON messages(sender, recipient);",
    "CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);"
]

