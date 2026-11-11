# Perbaikan Dongle Multi-User Kripto2

Paket ini menambahkan dukungan dua model penyimpanan dongle:

## 1. USB terpisah
Setiap user memakai flashdisk sendiri. File berada di root flashdisk:

    E:\secure_dongle.key

Pilih mode **USB terpisah (file di root)** saat registrasi atau saat membuat ulang dongle melalui tab Generator.

## 2. Satu USB untuk banyak user
Satu flashdisk menyimpan folder per user:

    E:\vandijk\secure_dongle.key
    E:\gerrard\secure_dongle.key

Pilih mode **USB bersama (folder per user)**. Fungsi verifikasi mencari folder username secara otomatis, sehingga kunci user lain tidak menghentikan pencarian.

## File yang diubah
- `modules/auth/dongle.py`: generator mendukung folder per user; verifier memeriksa seluruh kandidat root dan folder user; file milik user lain tidak langsung menghentikan pencarian.
- `modules/auth/auth_manager.py`: meneruskan pilihan mode penyimpanan saat registrasi.
- `app.py`: menambahkan pilihan mode pada form registrasi dan generator dongle.

## Penting saat memakai versi ini
1. Backup proyek dan file dongle lama sebelum mengganti source.
2. Ekstrak ZIP ini ke folder baru atau replace source proyek lama.
3. Jalankan dari folder proyek:

       python -m streamlit run app.py

4. Untuk USB bersama, buat ulang dongle tiap user dengan memilih **USB bersama (folder per user)**. File lama yang berada di root tidak otomatis dipindahkan.
5. Untuk USB terpisah, pastikan tiap flashdisk berisi dongle pemiliknya sendiri.
6. Jika root USB sudah berisi `secure_dongle.key` milik user lain, generator sekarang menolak menimpanya. Pilih USB lain atau gunakan mode USB bersama.

## Catatan kompatibilitas
Verifier tetap mendukung format lama di root USB dan `data/virtual_dongle`. Kunci yang sudah ada tetap menggunakan format payload HMAC-SHA256 dan AES-GCM sebelumnya.
