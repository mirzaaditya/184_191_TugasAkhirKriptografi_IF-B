# 🛡️ Secure Messenger (Aplikasi Pesan Rahasia Kriptografi)
**Tugas Akhir Mata Kuliah Kriptografi**  
Sistem Pesan Rahasia Multi-Akun Berbasis Pertahanan Berlapis (*Defense-in-Depth*) menggunakan Python & Streamlit.

---

## 🌟 Fitur Utama & Kriteria Kriptografi

1. **Otentikasi Tiga Faktor (3FA):**
   - **Hardware Dongle USB:** Validasi tanda tangan digital **HMAC-SHA256** dan token terenkripsi **AES-256-GCM** pada flashdisk fisik.
   - **Biometrik Wajah OpenCV:** Verifikasi wajah dari kamera langsung (webcam) menggunakan Haar Cascade Classifier dan ekualisasi histogram.
   - **Password Kriptografis:** Pengamanan kata sandi master dengan **PBKDF2-HMAC-SHA256** ($100.000$ iterasi) + 128-bit Salt unik.

2. **Super Enkripsi Pesan Teks:**
   - Pipeline bertingkat: $\text{Plaintext} \xrightarrow{\text{Vigenère (Klasik)}} \text{Intermediate} \xrightarrow{\text{AES-256-GCM (Modern)}} \text{Final Base64}$.
   - Dilengkapi visualisasi teks intermediate untuk keperluan demonstrasi sidang.

3. **Enkripsi Berkas Biner (File Encryption):**
   - Menggunakan algoritma terpisah: **ChaCha20-Poly1305** (AEAD Stream Cipher RFC 8439) dengan kunci derivasi independen (*Domain Separation*).
   - Menjaga integritas byte-for-byte dan memulihkan nama berkas asli secara otomatis.

4. **Basis Data Terenkripsi (SQLite Data-at-Rest):**
   - *Application-Level Field Encryption* menggunakan AES-256-GCM.
   - Kolom `encrypted_content`, `content_nonce`, dan `content_tag` terpisah. Teks asli tidak pernah bocor ke disk.
   - Fitur audit integritas otomatis untuk mendeteksi manipulasi database.

5. **Steganografi Multimedia (LSB):**
   - Pesan rahasia wajib dienkripsi **AES-256-GCM** terlebih dahulu sebelum disisipkan.
   - **Citra PNG:** LSB pada saluran warna RGB (Pillow + NumPy).
   - **Audio WAV:** LSB pada sampel amplitudo audio 16-bit PCM (`wave` + NumPy).
   - **Video Lossless:** Ekstraksi frame dengan OpenCV, penyisipan LSB, dan rekonstruksi lossless menggunakan **Codec FFV1**.

6. **Buku Besar Audit Blockchain:**
   - Rantai blok buatan sendiri menggunakan fungsi hash **SHA-256** dan konsensus **Proof-of-Work (PoW)**.
   - Mencatat hash transaksi pesan, berkas, dan log audit login.
   - Fungsi `validate_chain()` untuk mendeteksi manipulasi data atau rantai putus seketika.

---

## 🚀 Panduan Menjalankan Aplikasi

### 1. Kebutuhan Sistem & Pustaka
Pastikan dependensi telah terinstal:
```powershell
pip install -r requirements.txt
```

### 2. Menjalankan Antarmuka Web Streamlit
Jalankan perintah berikut di terminal:
```powershell
streamlit run app.py
```
Aplikasi akan otomatis terbuka pada browser di alamat: `http://localhost:8501`.

### 3. Menjalankan Pengujian Otomatis (Unit & Integration Tests)
Seluruh pengujian unit dan sistem dapat dijalankan dengan perintah:
```powershell
# Uji Modul Otentikasi 3FA
python tests/test_auth.py

# Uji Super Enkripsi & Enkripsi Berkas
python tests/test_crypto.py

# Uji Keamanan Basis Data SQLite
python tests/test_database.py

# Uji Steganografi Multimedia (PNG, WAV, Video FFV1)
python tests/test_stego.py

# Uji Blockchain Proof-of-Work
python tests/test_blockchain.py

# Uji Integrasi Sistem Penuh (End-to-End)
python tests/test_integration.py

# Uji Benchmark Kinerja Empiris
python tests/benchmark_crypto.py
```

---

## 👥 Pembagian Tugas Kelompok (3 Anggota)

| Anggota | Peran / Modul Utama | Tanggung Jawab Algoritma |
| :--- | :--- | :--- |
| **Anggota 1** | **Access Control & Storage Security** | Modul Otentikasi 3FA (Dongle USB, Biometrik OpenCV, Hasher PBKDF2) dan Skema Basis Data SQLite Terenkripsi |
| **Anggota 2** | **Core Cryptographic Engine** | Vigenère Cipher manual, AES-256-GCM, Pipeline Super Enkripsi Teks, dan Enkripsi Berkas ChaCha20-Poly1305 |
| **Anggota 3** | **Multimedia Stego & Blockchain** | Steganografi LSB (Citra PNG, Audio WAV, Video Lossless FFV1) dan Buku Besar Blockchain SHA-256 Proof-of-Work |

---

## 📄 Dokumen Laporan & Presentasi
- [LAPORAN_TUGAS_AKHIR.md](file:///c:/Users/Herang/Documents/Kripto2/LAPORAN_TUGAS_AKHIR.md) — Draf naskah laporan lengkap Bab 1 s.d. Bab 5 format akademis.
- [OUTLINE_PRESENTASI.md](file:///c:/Users/Herang/Documents/Kripto2/OUTLINE_PRESENTASI.md) — 12 Slide presentasi dan contekan tanya jawab (FAQ) dosen penguji.

