"""
Inisialisasi Modul Basis Data:
- schema: Definisi skema tabel SQLite (users, messages, audit_logs)
- secure_db: Database Manager dengan enkripsi data-at-rest (Field-Level AES-256-GCM)
"""
from modules.database.secure_db import SecureDatabase

__all__ = ["SecureDatabase"]

