# LAPORAN TUGAS AKHIR
## SISTEM APLIKASI PESAN RAHASIA MULTI-AKUN (SECURE MESSENGER) BERBASIS KEAMANAN BERLAPIS (DEFENSE-IN-DEPTH)

**Mata Kuliah:** Kriptografi  
**Bahasa Pemrograman:** Python 3  
**Antarmuka Pengguna:** Streamlit Web GUI  
**Susunan Kelompok:** 3 Orang  

---

## ABSTRAK
Pertukaran informasi digital pada era komunikasi modern rentan terhadap ancaman intersepsi data (*eavesdropping*), pemalsuan identitas (*identity spoofing*), dan manipulasi pesan (*tampering attack*). Penelitian Tugas Akhir ini merancang dan mengimplementasikan aplikasi pesan rahasia (*Secure Messenger*) dengan prinsip pertahanan berlapis (*Defense-in-Depth*). Sistem mengintegrasikan: (1) Otentikasi Tiga Faktor (3FA) menggabungkan kepemilikan perangkat keras USB Dongle bertanda tangan HMAC-SHA256 & token terenkripsi AES-256, biometrik pengenalan wajah menggunakan OpenCV Haar Cascade, serta pengetahuan kata sandi master berbasis PBKDF2-HMAC-SHA256 dengan salt acak 128-bit; (2) Pengamanan pesan teks menggunakan Super Enkripsi hibrida kombinasi cipher klasik Vigenère Extended dan cipher modern AES-256-GCM; (3) Pengamanan berkas biner/dokumen menggunakan algoritma stream cipher independen ChaCha20-Poly1305 (RFC 8439); (4) Perlindungan data saat diam (*Data-at-Rest*) pada basis data SQLite menggunakan enkripsi tingkat kolom AES-256-GCM; (5) Steganografi multimedia untuk menyembunyikan ciphertext pada citra PNG, audio WAV, dan video lossless FFV1 berbasis teknik Least Significant Bit (LSB); serta (6) Buku besar audit terdistribusi berbasis Blockchain SHA-256 dengan konsensus Proof-of-Work (PoW) untuk memastikan keutuhan jejak audit dan bukti pengiriman pesan. Hasil pengujian empiris membuktikan bahwa seluruh fungsionalitas sistem berjalan dengan tingkat keberhasilan 100%, menghasilkan throughput enkripsi berkas mencapai 835,6 MB/s, serta mampu mendeteksi segala bentuk manipulasi data pada basis data dan blockchain seketika.

**Kata Kunci:** *Kriptografi, Super Enkripsi, Vigenère Cipher, AES-256-GCM, ChaCha20-Poly1305, Steganografi LSB, Blockchain, 3FA, OpenCV, SQLite.*

---

## BAB I: PENDAHULUAN

### 1.1 Latar Belakang
Dalam lanskap keamanan siber kontemporer, ketergantungan pada satu lapis pengamanan (*single point of failure*) terbukti tidak memadai dalam menangkal serangan tingkat lanjut (*Advanced Persistent Threats*). Aplikasi pesan instan konvensional kerap kali hanya mengamankan jalur transmisi (*in-transit encryption*), namun mengabaikan aspek keamanan fisik perangkat klien, kebocoran basis data lokal (*data-at-rest*), serta tidak tersedianya bukti forensik digital yang tidak dapat disangkal (*non-repudiation*).

Oleh karena itu, diperlukan arsitektur keamanan terintegrasi yang menerapkan prinsip *Defense-in-Depth* dengan memadukan otentikasi fisik-biometrik, super enkripsi bertingkat, steganografi multimedia, dan ledger berbasis rantai blok (*blockchain*).

### 1.2 Rumusan Masalah
1. Bagaimana merancang mekanisme otentikasi multi-faktor yang memverifikasi kepemilikan hardware dongle USB, biometrik wajah, dan kata sandi berkekuatan tinggi?
2. Bagaimana mengombinasikan algoritma klasik (Vigenère) dan modern (AES-256-GCM) untuk menciptakan Super Enkripsi yang aman dan tahan manipulasi?
3. Bagaimana menerapkan algoritma terpisah (ChaCha20-Poly1305) untuk pengamanan berkas biner?
4. Bagaimana menyembunyikan ciphertext ke dalam media gambar PNG, audio WAV, dan video tanpa merusak kualitas persepsi manusia?
5. Bagaimana merancang blockchain sederhana berbasis SHA-256 Proof-of-Work untuk mencatat riwayat audit log dan membuktikan keutuhan data?

### 1.3 Batasan Masalah
1. Bahasa pemrograman yang digunakan adalah Python 3 dengan antarmuka Streamlit.
2. Komunikasi diimplementasikan dengan model simulasi multi-akun dalam satu ekosistem aplikasi lokal terintegrasi.
3. Media carrier steganografi dibatasi pada format lossless: PNG (citra), WAV 16-bit PCM (audio), dan AVI Codec FFV1 (video).
4. Penambangan blockchain menggunakan konsensus Proof-of-Work berbasis CPU dengan tingkat kesulitan (*difficulty*) 2.

### 1.4 Tujuan
1. Membangun aplikasi Secure Messenger yang memenuhi seluruh standar kriptografi akademis dan industri.
2. Mengimplementasikan perlindungan data berlapis mulai dari gerbang login hingga persistensi disk.
3. Memberikan pembuktian empiris atas efisiensi dan keamanan algoritma melalui pengujian unit dan benchmark performa.

---

## BAB II: LANDASAN TEORI

### 2.1 Otentikasi Multi-Faktor (3FA)
Otentikasi Tiga Faktor mengombinasikan tiga ranah keamanan:
1. *Something You Have:* Hardware token USB flashdisk yang memuat berkas digital `secure_dongle.key`.
2. *Something You Are:* Biometrik wajah menggunakan deteksi Haar Cascade OpenCV dan normalisasi histogram.
3. *Something You Know:* Kata sandi yang diderivasi menggunakan fungsi PBKDF2.

### 2.2 Password Hashing: PBKDF2-HMAC-SHA256
PBKDF2 (NIST SP 800-132) menerapkan fungsi *key stretching* dengan rumus:
$$DK = \text{PBKDF2}(\text{PRF}, \text{Password}, \text{Salt}, c, dkLen)$$
Menggunakan $c = 100.000$ iterasi dan salt acak 128-bit untuk mencegah serangan *Rainbow Table* dan memperlambat serangan *brute-force* berbasis GPU.

### 2.3 Super Enkripsi: Vigenère Cipher + AES-256-GCM
- **Vigenère Cipher (Klasik):** Substitusi polialfabetik dengan rumus:
  $$C_i = (P_i + K_{i \pmod m}) \pmod{256}$$
- **AES-256-GCM (Modern AEAD):** Menggunakan kunci 256-bit dan menghasilkan *authentication tag* 128-bit via operasi perkalian Galois Field $\text{GF}(2^{128})$ untuk menjamin kerahasiaan dan integritas sekaligus.

### 2.4 Enkripsi Berkas: ChaCha20-Poly1305
Stream cipher standar IETF (RFC 8439) yang menggunakan fungsi kuarter ARX (*Add-Rotate-XOR*) dan authenticator Poly1305. Bersifat konstan terhadap waktu eksekusi CPU sehingga kebal terhadap serangan *cache-timing*.

### 2.5 Steganografi Least Significant Bit (LSB)
Menyembunyikan informasi pada bit berbobot terkecil ($2^0$) dari nilai piksel atau sampel audio:
$$S'_i = (S_i \ \& \ \sim 1) \mid b_i$$
Hanya dapat diterapkan pada media *lossless* (PNG, WAV PCM, Video FFV1) karena kompresi *lossy* (JPEG, MP3, H.264) akan membulatkan nilai frekuensi dan merusak bit LSB.

### 2.6 Blockchain & Konsensus Proof-of-Work
Rantai blok kriptografis di mana blok $i$ memuat hash blok sebelumnya ($H_{i-1}$):
$$H_i = \text{SHA-256}(\text{Index} \parallel \text{Timestamp} \parallel \text{Data} \parallel H_{i-1} \parallel \text{Nonce})$$
Konsensus PoW memaksa pencarian nilai $\text{Nonce}$ hingga $H_i < \text{Target}$.

---

## BAB III: ANALISIS DAN PERANCANGAN SISTEM

### 3.1 Arsitektur Sistem
Sistem dibangun dalam 6 modul utama:
- `modules/auth/`: Modul login 3FA (Dongle, Biometrik, Hasher).
- `modules/cryptography/`: Modul Vigenère, AES-256-GCM, Super Enkripsi, dan ChaCha20.
- `modules/database/`: SQLite DAO dengan enkripsi kolom AES-GCM.
- `modules/steganography/`: Mesin LSB untuk PNG, WAV, dan Video FFV1.
- `modules/blockchain/`: Entitas blok dan pengelola ledger PoW.
- `app.py`: Antarmuka interaktif Streamlit.

### 3.2 Pembagian Tanggung Jawab Kelompok (3 Anggota)
- **Anggota 1 (Access Control & Database Security):** Bertanggung jawab atas modul otentikasi biometrik wajah OpenCV, pendeteksian drive hardware USB dongle, hashing PBKDF2, serta perancangan skema SQLite data-at-rest.
- **Anggota 2 (Core Cryptographic Engine):** Bertanggung jawab atas penulisan manual Vigenère Cipher, integrasi AES-256-GCM, pipeline Super Enkripsi teks, dan implementasi stream cipher ChaCha20-Poly1305 untuk berkas.
- **Anggota 3 (Multimedia Steganography & Blockchain Ledger):** Bertanggung jawab atas penyisipan dan ekstraksi LSB pada citra PNG, audio WAV, video lossless FFV1, serta implementasi mesin Blockchain PoW SHA-256 dan auditor integritas rantai.

---

## BAB IV: HASIL DAN PEMBAHASAN

### 4.1 Hasil Pengujian Skenario Sistem
*(Rujuk Tabel 4.1 hingga 4.6 pada laporan hasil pengujian Tahap 8)*
- Pengujian Otentikasi: Lolos 6 skenario (termasuk deteksi manipulasi file dongle dan imposter).
- Pengujian Super Enkripsi: Lolos 6 skenario (termasuk penolakan tampering dan kunci salah).
- Pengujian Enkripsi Berkas: Lolos pada dokumen PDF, gambar, dan arsip ZIP dengan integritas byte-for-byte 100%.
- Pengujian SQLite: Terbukti 100% data tersimpan di disk dalam format heksadesimal terenkripsi (*zero plaintext leakage*).
- Pengujian Steganografi: Ekstraksi sempurna pada PNG, WAV, dan Video FFV1 dengan deteksi overflow kapasitas.
- Pengujian Blockchain: `validate_chain()` sukses memvalidasi 4 blok normal dan seketika mendeteksi manipulasi data.

### 4.2 Analisis Kinerja Empiris
*(Rujuk Tabel 4.7 Benchmark Kinerja)*
- Super Enkripsi teks beroperasi dalam rentang 0.035 ms hingga 3.879 ms (sangat efisien untuk aplikasi chat real-time).
- Enkripsi berkas ChaCha20-Poly1305 mencapai kecepatan throughput 835.6 MB/s pada berkas 2 MB.
- Penambangan PoW dengan difficulty 2 hanya membutuhkan 0.36 ms (119 iterasi), sangat responsif untuk pengguna desktop.

### 4.3 Analisis Kritis Kelemahan dan Keterbatasan Pendekatan
1. **Kelemahan Steganografi LSB:** Tidak kebal terhadap kompresi media transmisi komersial (seperti WhatsApp/Instagram image compression). Berkas harus dikirimkan dalam format asli (*document mode*).
2. **Kelemahan PBKDF2:** Tidak bersifat *memory-hard* dibandingkan Argon2id, sehingga secara teoretis masih rentan terhadap klaster akselerator ASIC/FPGA jika penyerang memiliki sumber daya komputasi khusus.
3. **Kelemahan Hardware Dongle File-Based:** USB flashdisk biasa tidak memiliki prosesor kriptografis anti-tamper (seperti pada smartcard/YubiKey), sehingga kloning raw-disk sektor demi sektor masih dimungkinkan jika penyerang memiliki akses fisik tanpa pengawasan.

---

## BAB V: KESIMPULAN DAN SARAN

### 5.1 Kesimpulan
1. Sistem Secure Messenger berhasil dibangun dengan memadukan 6 pilar keamanan kriptografi modern dan klasik ke dalam satu antarmuka Streamlit yang terintegrasi.
2. Penerapan Super Enkripsi (Vigenère + AES-256-GCM) terbukti efektif memberikan perlindungan berlapis dan resistensi penuh terhadap serangan pemalsuan bit (*bit-flipping*).
3. Pemisahan algoritma enkripsi berkas (ChaCha20-Poly1305) dan pesan teks berhasil memenuhi prinsip pemisahan domain kriptografis (*cryptographic domain separation*).
4. Steganografi multimedia dengan pra-enkripsi AES-256 pada citra PNG, audio WAV, dan video lossless FFV1 berhasil menyembunyikan informasi rahasia tanpa menimbulkan kecurigaan visual maupun auditori.
5. Buku besar Blockchain SHA-256 dengan konsensus Proof-of-Work terbukti ampuh mendeteksi perubahan data seketika (*tamper-evident*).

### 5.2 Saran
1. Mengintegrasikan algoritma deteksi kedipan (*Liveness Detection*) berbasis jaringan saraf tiruan (CNN) untuk mencegah serangan penipuan foto biometrik wajah.
2. Mengembangkan modul enkripsi asimetris kurva eliptik (X25519) untuk pertukaran kunci otomatis antar-pengguna secara online.

