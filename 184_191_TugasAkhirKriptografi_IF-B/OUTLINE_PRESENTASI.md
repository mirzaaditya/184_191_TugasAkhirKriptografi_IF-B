# OUTLINE SLIDE PRESENTASI TUGAS AKHIR KRIPTOGRAFI
## "Aplikasi Pesan Rahasia (Secure Messenger) Berbasis Pertahanan Berlapis (Defense-in-Depth)"

**Format Presentasi:** 12 Slide Utama | **Alokasi Waktu:** 15 Menit Presentasi + 10 Menit Q&A  
**Pembagian Anggota:** 3 Orang (Setiap anggota membawakan modul yang menjadi tanggung jawabnya)  

---

### SLIDE 1: JUDUL & TIM PENGEMBANG
- **Judul:** Rancang Bangun Aplikasi Pesan Rahasia Multi-Akun dengan Otentikasi 3-Faktor, Super Enkripsi, Steganografi Multimedia, dan Audit Trail Blockchain
- **Mata Kuliah:** Kriptografi
- **Identitas Anggota & Pembagian Modul:**
  1. **Anggota 1:** Otentikasi 3FA (Dongle USB, Biometrik OpenCV, PBKDF2) & Keamanan SQLite Data-at-Rest
  2. **Anggota 2:** Mesin Super Enkripsi Teks (Vigenère + AES-256-GCM) & Enkripsi Berkas (ChaCha20-Poly1305)
  3. **Anggota 3:** Steganografi Multimedia (PNG, WAV, Video FFV1) & Ledger Blockchain Proof-of-Work

---

### SLIDE 2: LATAR BELAKANG & PERMASALAHAN KEAMANAN
- **Poin Utama:**
  - Kelemahan aplikasi pesan instan konvensional: Terlalu bergantung pada *single-layer security* (hanya TLS in-transit).
  - Bahaya kebocoran data saat diam (*Data-at-Rest*): File database lokal yang tidak terenkripsi rentan disalin penyerang.
  - Ketiadaan audit trail non-repudiation: Pengirim dapat menyangkal telah mengirimkan pesan tertentu.
- **Solusi yang Diusulkan:** Paradigma **Defense-in-Depth** (6 Lapisan Keamanan Terpadu).

---

### SLIDE 3: ARSITEKTUR SISTEM (DEFENSE-IN-DEPTH)
- **Visual:** Tampilkan diagram alir arsitektur sistem (Mermaid Diagram dari Tahap 1):
  - Lapisan 1: 3-Factor Authentication (Fisik, Biometrik, Pengetahuan)
  - Lapisan 2: Enkripsi Pesan Teks (Super Enkripsi) & Berkas (ChaCha20)
  - Lapisan 3: Steganografi Multimedia (Pre-AES + LSB pada PNG, WAV, Video)
  - Lapisan 4: Penyimpanan Basis Data SQLite Terenkripsi (Data-at-Rest)
  - Lapisan 5: Buku Besar Audit Trail Blockchain SHA-256 dengan PoW

---

### SLIDE 4: LAPISAN 1 — OTENTIKASI 3-FAKTOR (3FA) *(Dibawakan oleh Anggota 1)*
- **Faktor 1 (Possession):** Hardware Dongle USB. Menggunakan file `secure_dongle.key` yang ditandatangani secara digital dengan **HMAC-SHA256** dan memuat token terenkripsi **AES-256-GCM**.
- **Faktor 2 (Inherence):** Biometrik Wajah OpenCV. Lokalisasi wajah via Haar Cascade, ekualisasi histogram untuk normalisasi cahaya, dan pencocokan kemiripan $\ge 65\%$.
- **Faktor 3 (Knowledge):** Kata Sandi Master. Diderivasi dengan **PBKDF2-HMAC-SHA256** ($100.000$ iterasi) + salt acak 128-bit untuk mencegah serangan *Rainbow Table*.

---

### SLIDE 5: LAPISAN 2 — SUPER ENKRIPSI PESAN TEKS *(Dibawakan oleh Anggota 2)*
- **Konsep:** Penggabungan cipher klasik dan modern secara bertingkat (*cascaded*).
- **Alur Proses:**
  $$\text{Plaintext} \xrightarrow[\text{Modulo 256}]{\text{Vigenère (Klasik)}} \text{Intermediate Ciphertext} \xrightarrow[\text{AEAD 128-bit Tag}]{\text{AES-256-GCM (Modern)}} \text{Final Base64}$$
- **Keunggulan:**
  - Vigenère menyamarkan pola bahasa manusia alami.
  - AES-256-GCM menjamin kerahasiaan tingkat militer dan perlindungan terhadap serangan *bit-flipping* melalui Authentication Tag.

---

### SLIDE 6: LAPISAN 3 — ENKRIPSI BERKAS CHACHA20-POLY1305 *(Dibawakan oleh Anggota 2)*
- **Mengapa Algoritma Berbeda?** Memenuhi aturan pemisahan kunci dan domain kriptografis (*Domain Separation*).
- **Keunggulan ChaCha20-Poly1305 (RFC 8439):**
  - Stream cipher berbasis operasi ARX (Addition, Rotation, XOR) tanpa S-Box memori.
  - Secara alami kebal terhadap serangan *cache-timing attack* pada perangkat yang tidak memiliki modul perangkat keras AES-NI.
  - Performa sangat tinggi: Mencapai throughput **835,6 MB/s**.

---

### SLIDE 7: LAPISAN 4 — BASIS DATA TERENKRIPSI (DATA-AT-REST) *(Dibawakan oleh Anggota 1)*
- **Metode:** *Application-Level Field Encryption* menggunakan AES-256-GCM pada SQLite.
- **Bukti Keamanan Disk:** Teks asli tidak pernah disimpan dalam format teks biasa di disk.
- **Struktur Kolom:** Kolom `encrypted_content`, `content_nonce` (12 byte), dan `content_tag` (16 byte) terpisah secara transparan.
- **Deteksi Manipulasi:** Jika berkas `.db` diedit langsung menggunakan SQLite Browser di luar aplikasi, sistem seketika mendeteksi tag tidak cocok (*integrity failure*).

---

### SLIDE 8: LAPISAN 5 — STEGANOGRAFI MULTIMEDIA LSB *(Dibawakan oleh Anggota 3)*
- **Prinsip Utama:** Pesan rahasia **wajib dienkripsi AES-256 terlebih dahulu** sebelum disisipkan ke bit LSB (Least Significant Bit).
- **Tiga Media Carrier:**
  1. **Citra PNG:** Manipulasi LSB piksel warna RGB via Pillow + NumPy tervektorisasi.
  2. **Audio WAV:** Modifikasi LSB amplitudo sampel 16-bit PCM (perubahan hanya $\pm 0,003\%$, tidak terdengar oleh manusia).
  3. **Video Lossless FFV1:** Pemecahan frame dengan OpenCV, penyisipan LSB, dan rekonstruksi *bit-exact lossless* dengan codec FFV1.

---

### SLIDE 9: LAPISAN 6 — AUDIT TRAIL BLOCKCHAIN SHA-256 *(Dibawakan oleh Anggota 3)*
- **Struktur Blok:** `Index`, `Timestamp`, `Data (Hash Pesan/File/Audit)`, `Prev_Hash`, `Nonce (PoW)`, dan `Hash`.
- **Konsensus Proof-of-Work:** Menambang blok dengan mencari nilai nonce yang menghasilkan hash berawalan `"00..."`.
- **Fungsi `validate_chain()`:** Mampu memindai dan membuktikan seluruh riwayat transaksi utuh tanpa dapat dipalsukan secara retrospektif (*tamper-evident*).

---

### SLIDE 10: HASIL PENGUJIAN & BENCHMARK EMPIRIS
- **Tampilkan Ringkasan Tabel Pengujian:**
  - 100% Pengujian Fungsional & Kriptografi Lulus (Total 28 Uji Kasus).
  - Waktu Super Enkripsi Teks: Hanya $0,064\text{ ms}$ untuk 500 karakter.
  - Waktu Penyisipan Steganografi: $21,81\text{ ms}$ (PNG) dan $9,92\text{ ms}$ (WAV).
  - Waktu Penambangan PoW (Difficulty 2): Hanya $0,36\text{ ms}$ (119 iterasi), ideal untuk aplikasi pengguna interaktif.

---

### SLIDE 11: ANALISIS KELEMAHAN & KETERBATASAN SISTEM
- **Analisis Kritis untuk Laporan & Sidang:**
  1. *Kelemahan Steganografi LSB:* Rentan rusak jika berkas dikirim melalui media sosial yang menerapkan kompresi lossy (seperti WhatsApp image compression). Harus dikirim sebagai berkas murni (*uncompressed document*).
  2. *Kelemahan PBKDF2:* Tidak *memory-hard* dibandingkan Argon2id, namun memiliki portabilitas bawaan tanpa memerlukan kompilasi C.
  3. *Kelemahan Dongle File-Based:* USB flashdisk biasa rentan terhadap kloning sektor disk mentah (*raw sector image cloning*) jika penyerang memiliki akses fisik penuh tanpa pengawasan.

---

### SLIDE 12: KESIMPULAN & DEMO APLIKASI
- **Kesimpulan:** Seluruh kriteria Tugas Akhir berhasil dipenuhi secara modular, terdokumentasi, dan teruji secara matematis maupun empiris.
- **Sesi Demonstrasi Langsung (Live Demo):**
  - Demo 1: Pendaftaran akun baru & pembuatan kunci dongle ke flashdisk USB.
  - Demo 2: Login 3FA menggunakan kamera langsung webcam + USB key.
  - Demo 3: Kirim chat super enkripsi & periksa data mentah di SQLite Inspector.
  - Demo 4: Steganografi audio/video & pemutaran media langsung.
  - Demo 5: Klik tombol "Audit Rantai Blok" untuk memvalidasi integritas ledger.

---

## CONTEKAN TANYA JAWAB DOSEN PENGUJI (FAQ & DEFENSE STRATEGY)

Berikut adalah panduan taktis untuk menjawab pertanyaan kritis dosen saat sidang:

### Q1: Mengapa memakai Super Enkripsi jika AES-256 sendiri sudah sangat kuat dan belum terpecahkan?
> **Jawaban (Anggota 2):**  
> *"Benar Pak/Bu, secara matematis AES-256 belum pernah dipecahkan secara praktis (*brute-force resistance*). Namun dalam konteks akademis dan pertahanan berlapis (*Defense-in-Depth*), Super Enkripsi memberikan dua lapisan independen: Vigenère Cipher mengaburkan struktur linguistik awal (*confusion*), sedangkan AES-256-GCM menyediakan pengacakan tingkat tinggi (*diffusion*) sekaligus integritas otentikasi data (AEAD). Jika salah satu lapisan kunci bocor, penyerang tetap tidak dapat membaca isi pesan tanpa kunci dari lapisan lainnya."*

### Q2: Mengapa dongle USB tidak cukup hanya memeriksa keberadaan flashdisk biasa (misalnya hanya mengecek huruf drive E:\)?
> **Jawaban (Anggota 1):**  
> *"Jika hanya mengecek huruf drive atau keberadaan file teks biasa, penyerang dapat dengan mudah membuat folder atau file tiruan. Pada sistem kami, berkas `secure_dongle.key` menyimpan token acak yang dienkripsi dengan AES-256-GCM menggunakan kunci master sistem, serta ditandatangani secara kriptografis menggunakan **HMAC-SHA256**. Jika penyerang menyalin file atau mengubah isinya walau satu karakter, verifikasi tanda tangan HMAC akan langsung gagal (*tamper detection*)."*

### Q3: Mengapa sebelum disisipkan dengan LSB, pesan rahasia wajib dienkripsi AES terlebih dahulu?
> **Jawaban (Anggota 3):**  
> *"Ada dua alasan ilmiah Pak/Bu: Pertama, memenuhi Prinsip Kerckhoffs, yaitu keamanan steganografi tidak boleh bergantung pada kerahasiaan algoritma penyisipannya. Kedua, teks biasa memiliki bias statistik frekuensi karakter yang mudah dideteksi oleh analisis steganalisis (*Chi-Square attack*). Dengan mengenkripsi pesan menggunakan AES-256-GCM terlebih dahulu, bit-bit yang disisipkan memiliki nilai entropi acak seragam yang menyerupai noise alami sensor kamera/audio, sehingga kebal terhadap deteksi statistik steganalisis."*

### Q4: Mengapa untuk video Anda menggunakan codec FFV1, bukan MP4 atau H.264?
> **Jawaban (Anggota 3):**  
> *"Karena H.264 atau MP4 menggunakan kompresi lossy yang menerapkan kuantisasi frekuensi diskrit (DCT) dan estimasi pergerakan frame (P-frame/B-frame). Proses kuantisasi ini membulatkan nilai piksel sehingga bit LSB terkecil akan teracak dan hancur. Codec **FFV1** berbasis FFmpeg adalah codec preservasi digital yang menjamin rekonstruksi frame bersifat **bit-exact lossless** (selisih nilai piksel = 0), sehingga data stego tetap utuh 100% saat diekstraksi kembali."*

### Q5: Bagaimana blockchain mendeteksi jika ada orang yang mengedit riwayat pesan di database?
> **Jawaban (Anggota 1 & 3):**  
> *"Setiap kali pesan dikirim, sistem menghitung nilai hash SHA-256 kanonikal dari pesan tersebut dan mencatatnya ke dalam blok rantai blockchain yang telah ditambang dengan Proof-of-Work. Jika penyerang mengubah isi pesan di basis data SQLite, nilai hash pesan baru tidak akan cocok dengan hash yang tersimpan permanen di blockchain. Selain itu, jika penyerang mencoba mengubah data di dalam blockchain itu sendiri, fungsi `validate_chain()` akan mendeteksi ketidakcocokan hash blok atau terputusnya tautan `prev_hash` seketika."*

