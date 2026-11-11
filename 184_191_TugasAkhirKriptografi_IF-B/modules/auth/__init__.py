"""
Modul Autentikasi Pengguna:
- hasher: Pengelolaan hashing password menggunakan PBKDF2-HMAC-SHA256 + Salt
- dongle: Pendeteksian USB flashdisk fisik dan verifikasi tanda tangan digital file kunci
- biometric: Deteksi dan verifikasi wajah pengguna menggunakan OpenCV
- auth_manager: Koordinator 3-Factor Authentication (Dongle + Wajah + Password)
"""

