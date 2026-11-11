@echo off
TITLE Secure Messenger - Unit & Integration Test Runner
COLOR 0B
cls
echo ==============================================================================
echo        MENJALANKAN SELURUH PENGUJIAN OTOMATIS & BENCHMARK KRIPTOGRAFI
echo ==============================================================================
echo.

echo [1/7] Menjalankan Uji Otentikasi 3-Faktor...
python tests/test_auth.py
echo.

echo [2/7] Menjalankan Uji Super Enkripsi & Enkripsi Berkas...
python tests/test_crypto.py
echo.

echo [3/7] Menjalankan Uji Keamanan Basis Data SQLite (Data-at-Rest)...
python tests/test_database.py
echo.

echo [4/7] Menjalankan Uji Steganografi Multimedia (PNG, WAV, Video FFV1)...
python tests/test_stego.py
echo.

echo [5/7] Menjalankan Uji Rantai Blok & Konsensus Proof-of-Work...
python tests/test_blockchain.py
echo.

echo [6/7] Menjalankan Uji Integrasi Sistem Penuh (End-to-End)...
python tests/test_integration.py
echo.

echo [7/7] Menjalankan Uji Pengukuran Kinerja Empiris (Benchmark)...
python tests/benchmark_crypto.py
echo.

echo ==============================================================================
echo               SELURUH PENGUJIAN SELESAI DIJALANKAN!
echo ==============================================================================
pause

