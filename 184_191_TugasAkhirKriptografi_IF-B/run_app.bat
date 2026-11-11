@echo off
TITLE Secure Messenger - Tugas Akhir Kriptografi
COLOR 0A
cls
echo ==============================================================================
echo        MEMULAI APLIKASI SECURE MESSENGER (STREAMLIT GUI)
echo ==============================================================================
echo Mata Kuliah : Kriptografi
echo Sistem      : Otentikasi 3FA, Super Enkripsi, Steganografi, Basis Data & Blockchain
echo.
echo Membuka aplikasi pada browser (http://localhost:8501)...
echo Tekan Ctrl+C di terminal ini untuk menghentikan aplikasi.
echo ==============================================================================
echo.

python -m streamlit run app.py

pause

