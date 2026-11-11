# PANDUAN KOREOGRAFI DEMO LANGSUNG DI HADAPAN DOSEN PENGUJI (LIVE DEMO GUIDE)
## "Aplikasi Pesan Rahasia (Secure Messenger)"

Panduan ini dirancang untuk kelompok 3 orang agar demonstrasi aplikasi saat presentasi sebelum UAS berjalan mulus, terstruktur, tidak canggung, dan memukau dewan penguji.

**Total Durasi Demo:** 7–10 Menit  
**Pelaksana:** Anggota 1, Anggota 2, dan Anggota 3  

---

### PERSIAPAN SEBELUM TAMPIL (H-15 Menit)
1. Tancapkan USB Flashdisk fisik yang telah disiapkan ke port laptop.
2. Pastikan webcam internal laptop berfungsi normal dan pencahayaan ruangan cukup.
3. Buka terminal atau cukup klik dua kali berkas `run_app.bat`.
4. Browser akan membuka antarmuka Streamlit di `http://localhost:8501`.
5. Siapkan tab kedua di browser untuk menampilkan berkas laporan atau slide presentasi.

---

### BABAK 1: DEMONSTRASI OTENTIKASI 3-FAKTOR (3FA) (Menit 01:00 – 03:00)
**Pemandu:** Anggota 1

1. **Pendaftaran Akun Baru (User 'Alice'):**
   - Klik tab **📝 Pendaftaran Pengguna Baru**.
   - Masukkan username: `alice` dan password: `PasswordAlice123!`.
   - Pilih drive USB Flashdisk Anda sebagai target pembuatan kunci.
   - Arahkan wajah ke kamera, klik tombol **Ambil Foto**.
   - Klik tombol **Daftarkan Pengguna Baru**.
   - *Penjelasan Anggota 1 ke Dosen:*
     > *"Bisa dilihat Pak/Bu, saat registrasi, sistem langsung mengenkripsi foto wajah untuk rujukan biometrik, membuat berkas `secure_dongle.key` bertanda tangan HMAC-SHA256 pada flashdisk fisik, serta melakukan hashing kata sandi dengan PBKDF2 100.000 iterasi dengan salt acak 128-bit."*

2. **Uji Kasus Negatif (Penolakan Imposter & Dongle Dicabut):**
   - Buka tab **🔐 Masuk (3-Factor Login)**.
   - Coba masukkan password salah $\rightarrow$ Sistem langsung menolak: `[FAKTOR 3 DITOLAK] Kata sandi salah`.
   - Coba tutup kamera dengan tangan $\rightarrow$ Sistem menolak: `Wajah tidak terdeteksi`.
   - *Poin Penilaian Dosen:* Menunjukkan bahwa sistem memiliki penanganan kesalahan (*error handling*) yang tangguh dan tidak membiarkan akses liar.

3. **Login Berhasil:**
   - Arahkan wajah asli, masukkan password benar, pilih drive flashdisk.
   - Klik **🚀 Verifikasi 3FA & Masuk ke Aplikasi**.
   - Masuk ke dashboard dengan badge hijau: `🔒 3FA Authenticated`.

---

### BABAK 2: DEMONSTRASI SUPER ENKRIPSI PESAN TEKS & BERKAS (Menit 03:00 – 05:30)
**Pemandu:** Anggota 2

1. **Kirim Pesan Chat Super Enkripsi:**
   - Pilih menu **💬 Chat Super Enkripsi (Teks)**.
   - Pilih penerima (misal `bob`).
   - Tulis pesan: `"DOKUMEN RAHASIA NEGARA: Operasi Garuda dimulai malam ini!"`.
   - Masukkan kunci Vigenère dan kunci AES-256.
   - Klik **Kirim 🚀**.
   - Buka expander **🔍 Visualisasi Tahapan Super Enkripsi**:
     - Tunjukkan Plaintext Asli.
     - Tunjukkan Intermediate Ciphertext (setelah Vigenère Cipher).
     - Tunjukkan Final Ciphertext Base64 (setelah AES-256-GCM + Nonce + Tag).
   - *Penjelasan Anggota 2 ke Dosen:*
     > *"Ini adalah keunggulan Super Enkripsi kami Pak/Bu. Teks mengalami transformasi klasik Vigenère untuk mengaburkan pola bahasa, lalu dibungkus enkripsi modern AES-256-GCM yang menyematkan 128-bit Authentication Tag untuk memastikan tidak ada bit yang bisa dimodifikasi penyerang."*

2. **Kirim Berkas Rahasia (ChaCha20-Poly1305):**
   - Pilih menu **📁 Kirim Berkas Rahasia (ChaCha20)**.
   - Unggah sembarang file (PDF dokumen atau gambar).
   - Klik **🔒 Enkripsi Berkas**.
   - Unduh file `.enc` yang dihasilkan.
   - Tunjukkan tab dekripsi: unggah file `.enc`, masukkan kunci, dan klik **🔓 Dekripsi**. File asli kembali utuh 100% byte-for-byte!
   - *Penjelasan Anggota 2:*
     > *"Sesuai instruksi Bapak/Ibu dosen, algoritma berkas sepenuhnya berbeda dari pesan teks. Kami memakai stream cipher modern ChaCha20-Poly1305 yang kebal terhadap serangan cache-timing dan memiliki throughput hingga 835 MB/s."*

---

### BABAK 3: DEMONSTRASI STEGANOGRAFI MULTIMEDIA (Menit 05:30 – 07:30)
**Pemandu:** Anggota 3

1. **Steganografi Audio WAV:**
   - Pilih menu **🎨 Steganografi Multimedia (LSB)** $\rightarrow$ Pilih **🎵 Audio (WAV)**.
   - Masukkan pesan rahasia: `"Koordinat pendaratan rahasia: -6.2088, 106.8456"`.
   - Klik **🎵 Buat Audio WAV Uji Otomatis** (atau upload file WAV Anda).
   - Klik **🎵 Sisipkan ke Audio WAV**.
   - Putar audio hasil stego di browser $\rightarrow$ Suara tetap jernih tanpa distorsi suara sama sekali!
   - Tunjukkan tab ekstraksi: masukkan kunci AES, klik ekstraksi $\rightarrow$ Pesan rahasia kembali terbaca utuh!

2. **Steganografi Video Lossless (FFV1):**
   - Pilih sub-menu **🎬 Video (Lossless AVI)**.
   - Klik **🎬 Buat Video Uji Otomatis**, lalu klik **🎬 Sisipkan ke Video Lossless**.
   - *Penjelasan Anggota 3:*
     > *"Sebelum disisipkan ke bit LSB, pesan rahasia selalu kami enkripsi AES-256 terlebih dahulu agar bit-bitnya memiliki entropi acak seragam menyerupai noise alami. Selain itu, kami menggunakan codec FFV1 agar proses kompresi video bersifat bit-exact lossless dan bit LSB tidak hilang."*

---

### BABAK 4: DEMONSTRASI INSPEKTUR SQLITE & AUDIT BLOCKCHAIN (Menit 07:30 – 09:30)
**Pemandu:** Anggota 1 & Anggota 3

1. **Inspektur Basis Data (SQLite Data-at-Rest):**
   - Pilih menu **🗄️ Inspektur Basis Data (SQLite)**.
   - Tunjukkan tabel data mentah:
     - Tunjukkan kolom `encrypted_content`, `content_nonce`, dan `content_tag`.
   - *Penjelasan Anggota 1:*
     > *"Ini bukti fisik bahwa teks pesan yang baru saja kami kirim tidak tersimpan dalam bentuk teks biasa di disk. Jika ada orang mencuri harddisk atau membuka berkas `.db` dengan SQLite Browser, yang terlihat hanyalah deretan karakter biner heksadesimal acak."*

2. **Blockchain Explorer & Live Tamper Test:**
   - Pilih menu **⛓️ Blockchain Ledger & Auditor**.
   - Perlihatkan tumpukan kartu blok:
     - Blok #0: Genesis Block.
     - Blok #1: Bukti Log Audit Login Alice.
     - Blok #2: Bukti Transaksi Pesan (Hash SHA-256).
     - Blok #3: Bukti Transaksi Berkas Terenkripsi.
   - Klik tombol **🔍 Audit Keutuhan Rantai (validate_chain)**:
     - Muncul banner hijau: `🛡️ STATUS AMAN: Seluruh rantai valid! Tanpa manipulasi data.`
   - *Klimaks Demonstrasi (Anggota 3):*
     > *"Setiap transaksi pesan dan log login terikat permanen ke blockchain dengan konsensus Proof-of-Work. Jika ada pihak yang mencoba mengubah database atau memalsukan log, tautan `prev_hash` akan putus seketika dan langsung terdeteksi."*

---

### KATA PENUTUP PRESENTASI (Menit 09:30 – 10:00)
*"Demikian demonstrasi sistem Secure Messenger dari kelompok kami. Seluruh 6 kriteria keamanan dan 9 tahapan tugas akhir telah kami implementasikan secara modular dan teruji 100%. Kami siap menerima pertanyaan dan masukan dari Bapak/Ibu dewan penguji. Terima kasih!"*

