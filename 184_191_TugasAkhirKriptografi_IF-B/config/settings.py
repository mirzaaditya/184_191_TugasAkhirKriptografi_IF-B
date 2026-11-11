# ==============================================================================
# KONFIGURASI GLOBAL SISTEM APLIKASI PESAN RAHASIA
# ==============================================================================
import os
from pathlib import Path

# Direktori Dasar (Root Project)
BASE_DIR = Path(__file__).resolve().parent.parent

# Direktori Penyimpanan Data Lokal
DATA_DIR = BASE_DIR / "data"
REFERENCE_FACES_DIR = DATA_DIR / "reference_faces"
DATABASE_PATH = DATA_DIR / "app_database.db"
BLOCKCHAIN_LEDGER_PATH = DATA_DIR / "blockchain_ledger.json"

# Direktori Virtual Dongle (Fallback untuk simulasi tanpa USB fisik)
VIRTUAL_DONGLE_DIR = DATA_DIR / "virtual_dongle"

# Pastikan direktori penting ada saat runtime
for directory in [DATA_DIR, REFERENCE_FACES_DIR, VIRTUAL_DONGLE_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Parameter Kriptografi PBKDF2
PBKDF2_ALGORITHM = "SHA256"
PBKDF2_ITERATIONS = 100_000   # Standar rekomendasi OWASP / NIST
PBKDF2_SALT_BYTES = 16        # 128-bit cryptographically secure salt
PBKDF2_KEY_LENGTH = 32        # 256-bit derived key

# Parameter Dongle USB
DONGLE_KEY_FILENAME = "secure_dongle.key"
# Master secret aplikasi untuk memvalidasi tanda tangan HMAC pada dongle key
DONGLE_MASTER_SECRET = b"SECURE_MESSENGER_DONGLE_SIGNING_KEY_2026_MASTER"

# Parameter Biometrik Wajah (OpenCV)
FACE_SIMILARITY_THRESHOLD = 0.65  # Skor kemiripan minimal (0.0 - 1.0) untuk lolos
FACE_TARGET_SIZE = (200, 200)     # Normalisasi dimensi wajah (lebar, tinggi)

# Parameter Blockchain
BLOCKCHAIN_POW_DIFFICULTY = 2     # Jumlah nol pembuka (prefix '00') untuk Proof-of-Work

