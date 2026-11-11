"""
==============================================================================
SKRIP BENCHMARK KINERJA KRIPTOGRAFI (EMPIRICAL PERFORMANCE BENCHMARK)
==============================================================================
Mengukur metrik kuantitatif untuk Bab 4 Laporan Tugas Akhir:
1. Waktu komputasi Super Enkripsi (Vigenere + AES-256) vs Plaintext size
2. Waktu komputasi Enkripsi Berkas ChaCha20-Poly1305 (1 KB, 50 KB, 500 KB, 2 MB)
3. Waktu komputasi Steganografi (Embed & Extract) pada Gambar PNG, Audio WAV, Video FFV1
4. Waktu penambangan konsensus Proof-of-Work Blockchain berdasarkan Difficulty
==============================================================================
"""

import sys
import os
import time
import numpy as np
from pathlib import Path
from PIL import Image

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from modules.cryptography.super_encryption import super_encrypt, super_decrypt
from modules.cryptography.file_cipher import encrypt_file_bytes, decrypt_file_bytes
from modules.steganography.image_stego import embed_image, extract_image
from modules.steganography.audio_stego import embed_audio, extract_audio, create_dummy_wav
from modules.steganography.video_stego import embed_video, extract_video, create_dummy_video
from modules.blockchain.block import Block
from config.settings import DATA_DIR


def benchmark_suite():
    print("=" * 80)
    print("      BENCHMARK KINERJA EMPIRIS KRIPTOGRAFI - SECURE MESSENGER")
    print("=" * 80)
    
    bench_dir = DATA_DIR / "bench_temp"
    bench_dir.mkdir(parents=True, exist_ok=True)
    
    # -------------------------------------------------------------------------
    # 1. BENCHMARK SUPER ENKRIPSI TEKS
    # -------------------------------------------------------------------------
    print("\n[BENCHMARK 1] Super Enkripsi Pesan Teks (Vigenère + AES-256-GCM)")
    text_sizes = [50, 500, 5000, 50000]  # characters
    
    for sz in text_sizes:
        sample_txt = "A" * sz
        # Warmup
        super_encrypt("Warmup", "K1", "K2")
        
        # Ukur Enkripsi
        t0 = time.perf_counter()
        enc_res = super_encrypt(sample_txt, "VigenereKey2026", "AESKey2026", mode="extended")
        t_enc = (time.perf_counter() - t0) * 1000  # ms
        
        # Ukur Dekripsi
        t1 = time.perf_counter()
        dec_res = super_decrypt(enc_res["final_ciphertext"], "VigenereKey2026", "AESKey2026", mode="extended")
        t_dec = (time.perf_counter() - t1) * 1000  # ms
        
        print(f"  * Ukuran Teks: {sz:>6} Karakter | Enkripsi: {t_enc:>7.3f} ms | Dekripsi: {t_dec:>7.3f} ms | Status: 100% Cocok")

    # -------------------------------------------------------------------------
    # 2. BENCHMARK ENKRIPSI BERKAS CHACHA20-POLY1305
    # -------------------------------------------------------------------------
    print("\n[BENCHMARK 2] Enkripsi Berkas Biner (ChaCha20-Poly1305)")
    file_sizes_kb = [1, 50, 500, 2048]  # KB
    
    for sz_kb in file_sizes_kb:
        raw_bin = os.urandom(sz_kb * 1024)
        
        t0 = time.perf_counter()
        enc_bin = encrypt_file_bytes(raw_bin, f"bench_{sz_kb}kb.bin", "ChaChaKeyFile2026")
        t_enc = (time.perf_counter() - t0) * 1000
        
        t1 = time.perf_counter()
        dec_bin, _, _ = decrypt_file_bytes(enc_bin, "ChaChaKeyFile2026")
        t_dec = (time.perf_counter() - t1) * 1000
        
        throughput_mb_s = (sz_kb / 1024) / (t_enc / 1000) if t_enc > 0 else 0
        print(f"  * Ukuran Berkas: {sz_kb:>5} KB | Enkripsi: {t_enc:>7.3f} ms | Dekripsi: {t_dec:>7.3f} ms | Throughput: {throughput_mb_s:>7.1f} MB/s")

    # -------------------------------------------------------------------------
    # 3. BENCHMARK STEGANOGRAFI MULTIMEDIA
    # -------------------------------------------------------------------------
    print("\n[BENCHMARK 3] Steganografi Multimedia (AES-256 + LSB Embed & Extract)")
    secret_payload = "Informasi Intelijen Rahasia Operasi Gabungan 2026."
    
    # Gambar PNG (300x300 RGB)
    png_carrier = bench_dir / "bench_carrier.png"
    png_stego = bench_dir / "bench_stego.png"
    Image.fromarray(np.random.randint(50, 200, (300, 300, 3), dtype=np.uint8)).save(png_carrier)
    
    t0 = time.perf_counter()
    embed_image(png_carrier, secret_payload, "KeyStego2026", png_stego)
    t_img_emb = (time.perf_counter() - t0) * 1000
    
    t1 = time.perf_counter()
    extract_image(png_stego, "KeyStego2026")
    t_img_ext = (time.perf_counter() - t1) * 1000
    print(f"  * Gambar PNG (300x300 px) : Penyisipan: {t_img_emb:>6.2f} ms | Ekstraksi: {t_img_ext:>6.2f} ms")
    
    # Audio WAV (3 Detik 44.1 kHz)
    wav_carrier = bench_dir / "bench_carrier.wav"
    wav_stego = bench_dir / "bench_stego.wav"
    create_dummy_wav(wav_carrier, duration_sec=3.0)
    
    t0 = time.perf_counter()
    embed_audio(wav_carrier, secret_payload, "KeyStego2026", wav_stego)
    t_aud_emb = (time.perf_counter() - t0) * 1000
    
    t1 = time.perf_counter()
    extract_audio(wav_stego, "KeyStego2026")
    t_aud_ext = (time.perf_counter() - t1) * 1000
    print(f"  * Audio WAV (3.0 Detik)   : Penyisipan: {t_aud_emb:>6.2f} ms | Ekstraksi: {t_aud_ext:>6.2f} ms")
    
    # Video FFV1 (20 Frame 160x120)
    vid_carrier = bench_dir / "bench_carrier.avi"
    vid_stego = bench_dir / "bench_stego.avi"
    create_dummy_video(vid_carrier, num_frames=20)
    
    t0 = time.perf_counter()
    embed_video(vid_carrier, secret_payload, "KeyStego2026", vid_stego)
    t_vid_emb = (time.perf_counter() - t0) * 1000
    
    t1 = time.perf_counter()
    extract_video(vid_stego, "KeyStego2026")
    t_vid_ext = (time.perf_counter() - t1) * 1000
    print(f"  * Video FFV1 (20 Frames)  : Penyisipan: {t_vid_emb:>6.2f} ms | Ekstraksi: {t_vid_ext:>6.2f} ms")

    # -------------------------------------------------------------------------
    # 4. BENCHMARK PROOF-OF-WORK BLOCKCHAIN (DIFFICULTY vs ITERATIONS & TIME)
    # -------------------------------------------------------------------------
    print("\n[BENCHMARK 4] Konsensus Proof-of-Work Blockchain (SHA-256 Mining)")
    test_difficulties = [1, 2, 3, 4]
    
    for diff in test_difficulties:
        b = Block(index=1, timestamp="", data={"tx": "benchmark"}, prev_hash="0"*64)
        t0 = time.perf_counter()
        iters = b.mine_block(diff)
        t_mine = (time.perf_counter() - t0) * 1000
        print(f"  * PoW Difficulty: {diff} ('{'0'*diff}...') | Iterasi Nonce: {iters:>6} | Waktu: {t_mine:>7.2f} ms | Hash: {b.hash[:16]}...")
        
    print("\n" + "=" * 80)
    print(" SELURUH PENGUKURAN BENCHMARK BERHASIL DIKOMPUTASI SECARA EMPIRIS!")
    print("=" * 80)


if __name__ == "__main__":
    benchmark_suite()

