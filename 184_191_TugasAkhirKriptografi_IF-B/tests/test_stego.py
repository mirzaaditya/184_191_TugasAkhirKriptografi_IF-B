"""
==============================================================================
SKRIP PENGUJIAN OTOMATIS: MODUL STEGANOGRAFI MULTIMEDIA (TAHAP 5)
==============================================================================
Menjalankan serangkaian pengujian steganografi komprehensif:
1. Steganografi Gambar (PNG): Pra-enkripsi AES-256 + LSB, ekstraksi, uji kunci salah & kapasitas
2. Steganografi Audio (WAV 16-bit PCM): LSB sampel, ekstraksi, verifikasi integritas
3. Steganografi Video (AVI Lossless FFV1): Ekstraksi frame, penyisipan LSB, rekonstruksi & ekstraksi
4. Uji Penolakan Media Pembawa Polos (Non-stego detection)
==============================================================================
"""

import sys
import numpy as np
from pathlib import Path
from PIL import Image

# Tambahkan root proyek ke sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from modules.steganography.image_stego import embed_image, extract_image
from modules.steganography.audio_stego import embed_audio, extract_audio, create_dummy_wav, create_dummy_mp3
from modules.steganography.video_stego import embed_video, extract_video, create_dummy_video, create_dummy_mp4
from config.settings import DATA_DIR


def run_tests():
    print("=" * 75)
    print("      PENGUJIAN MODUL STEGANOGRAFI MULTIMEDIA (TAHAP 5)")
    print("=" * 75)
    
    stego_test_dir = DATA_DIR / "test_stego_output"
    stego_test_dir.mkdir(parents=True, exist_ok=True)
    
    secret_text = "INFORMASI INTELIJEN #99: Operasi senyap akan dimulai pukul 23:45 WIB. 🛡️"
    aes_stego_key = "KunciRahasiaSteganografiAES2026!"
    wrong_key = "KunciSalahPastiDitolakTag999!"
    
    # -------------------------------------------------------------------------
    # UJI 1: STEGANOGRAFI GAMBAR (PNG)
    # -------------------------------------------------------------------------
    print("\n[UJI 1] Steganografi Gambar: PNG (Pillow + NumPy LSB)")
    
    # 1A. Buat citra pembawa sintetis (200x200 RGB)
    carrier_png = stego_test_dir / "carrier_image.png"
    stego_png = stego_test_dir / "stego_image.png"
    
    # Buat gradien warna cerah
    grad = np.zeros((200, 200, 3), dtype=np.uint8)
    grad[:, :, 0] = np.linspace(0, 255, 200, dtype=np.uint8)
    grad[:, :, 1] = 120
    grad[:, :, 2] = np.linspace(255, 0, 200, dtype=np.uint8)
    Image.fromarray(grad).save(carrier_png)
    
    # 1B. Sisipkan pesan rahasia (AES-256-GCM -> LSB)
    res_img = embed_image(carrier_png, secret_text, aes_stego_key, stego_png)
    print(f"  * Citra Stego Dihasilkan : {Path(res_img['output_path']).name}")
    print(f"  * Kapasitas Terpakai     : {res_img['capacity_usage_percent']}% ({res_img['embedded_bits']} bits)")
    print(f"  * Dimensi Citra          : {res_img['dimensions']}")
    assert Path(stego_png).exists(), "GAGAL: Berkas citra stego tidak terbuat!"
    
    # 1C. Ekstraksi pesan dengan kunci benar
    extracted_text = extract_image(stego_png, aes_stego_key)
    print(f"  * Pesan Terekstraksi     : '{extracted_text}'")
    assert extracted_text == secret_text, "GAGAL: Pesan hasil ekstraksi citra tidak cocok dengan aslinya!"
    print("  [PASSED] Ekstraksi steganografi gambar PNG 100% Cocok dan Utuh.")
    
    # 1D. Uji Kunci AES Salah pada Gambar
    try:
        extract_image(stego_png, wrong_key)
        assert False, "GAGAL: Kunci AES salah harus ditolak oleh authentication tag!"
    except ValueError as e:
        print(f"  * Penolakan Kunci Salah  : {e}")
        print("  [PASSED] Ekstraksi dengan kunci salah berhasil digagalkan oleh AES-GCM.")
        
    # 1E. Uji Pembawa Polos (Bukan stego)
    try:
        extract_image(carrier_png, aes_stego_key)
        assert False, "GAGAL: Citra polos harus ditolak karena tidak memiliki header stego!"
    except ValueError:
        print("  [PASSED] Sistem mengenali dan menolak citra polos tanpa muatan steganografi.")

    # -------------------------------------------------------------------------
    # UJI 2: STEGANOGRAFI AUDIO (WAV)
    # -------------------------------------------------------------------------
    print("\n[UJI 2] Steganografi Audio: WAV (wave + NumPy LSB Sampel 16-bit)")
    
    carrier_wav = stego_test_dir / "carrier_audio.wav"
    stego_wav = stego_test_dir / "stego_audio.wav"
    create_dummy_wav(carrier_wav, duration_sec=2.0)
    
    # 2A. Sisipkan pesan rahasia ke audio
    res_audio = embed_audio(carrier_wav, secret_text, aes_stego_key, stego_wav)
    print(f"  * Audio Stego Dihasilkan : {Path(res_audio['output_path']).name}")
    print(f"  * Sampel Terpakai        : {res_audio['capacity_usage_percent']}% ({res_audio['embedded_bits']} bits)")
    print(f"  * Durasi & Sample Rate   : {res_audio['duration_sec']}s @ {res_audio['sample_rate']} Hz")
    assert Path(stego_wav).exists(), "GAGAL: Berkas audio stego tidak terbuat!"
    
    # 2B. Ekstraksi pesan dengan kunci benar
    extracted_audio_msg = extract_audio(stego_wav, aes_stego_key)
    print(f"  * Pesan Audio Terekstrak : '{extracted_audio_msg}'")
    assert extracted_audio_msg == secret_text, "GAGAL: Pesan hasil ekstraksi audio tidak cocok!"
    print("  [PASSED] Ekstraksi steganografi audio WAV 100% Cocok dan Utuh.")
    
    # 2C. Uji Kunci Salah pada Audio
    try:
        extract_audio(stego_wav, wrong_key)
        assert False, "GAGAL: Kunci AES salah pada audio harus ditolak!"
    except ValueError:
        print("  [PASSED] Penolakan kunci salah pada audio berhasil.")

    # -------------------------------------------------------------------------
    # UJI 3: STEGANOGRAFI VIDEO (LOSSLESS AVI / FFV1)
    # -------------------------------------------------------------------------
    print("\n[UJI 3] Steganografi Video: OpenCV Frame Breaking + Lossless Codec (FFV1)")
    
    carrier_vid = stego_test_dir / "carrier_video.avi"
    stego_vid = stego_test_dir / "stego_video.avi"
    create_dummy_video(carrier_vid, num_frames=15, width=160, height=120)
    
    # 3A. Sisipkan pesan rahasia ke video
    res_vid = embed_video(carrier_vid, secret_text, aes_stego_key, stego_vid)
    print(f"  * Video Stego Dihasilkan : {Path(res_vid['output_path']).name}")
    print(f"  * Frame Terproses        : {res_vid['total_frames']} frames")
    print(f"  * Codec Digunakan        : {res_vid['codec']}")
    print(f"  * Kapasitas Terpakai     : {res_vid['capacity_usage_percent']}%")
    assert Path(stego_vid).exists(), "GAGAL: Berkas video stego tidak terbuat!"
    
    # 3B. Ekstraksi pesan dari video stego
    extracted_vid_msg = extract_video(stego_vid, aes_stego_key)
    print(f"  * Pesan Video Terekstrak : '{extracted_vid_msg}'")
    assert extracted_vid_msg == secret_text, "GAGAL: Pesan hasil ekstraksi video tidak cocok!"
    print("  [PASSED] Ekstraksi steganografi video lossless FFV1 100% Cocok dan Utuh.")
    
    # 3C. Uji Kunci Salah pada Video
    try:
        extract_video(stego_vid, wrong_key)
        assert False, "GAGAL: Kunci AES salah pada video harus ditolak!"
    except ValueError:
        print("  [PASSED] Penolakan kunci salah pada video berhasil.")

    # -------------------------------------------------------------------------
    # UJI 4: PENANGANAN KAPASITAS MELEBIHI BATAS (OVERFLOW TEST)
    # -------------------------------------------------------------------------
    print("\n[UJI 4] Pengujian Penanganan Kesalahan: Kapasitas Media Tidak Cukup")
    tiny_png = stego_test_dir / "tiny.png"
    # Citra kerdil 5x5 piksel = 75 bits kapasitas
    Image.fromarray(np.zeros((5, 5, 3), dtype=np.uint8)).save(tiny_png)
    
    try:
        embed_image(tiny_png, "Pesan ini pasti terlalu panjang untuk muat di 5x5 piksel!", aes_stego_key, stego_test_dir / "overflow.png")
        assert False, "GAGAL: Sistem harus menolak jika kapasitas media tidak cukup!"
    except ValueError as e:
        print(f"  * Pesan Error Kapasitas Terdeteksi: {e}")
        print("  [PASSED] Kapasitas media yang tidak memadai berhasil dicegah dengan pesan error yang jelas.")

    # -------------------------------------------------------------------------
    # UJI 5: STEGANOGRAFI AUDIO MP3 (CONTAINER INJECTION)
    # -------------------------------------------------------------------------
    print("\n[UJI 5] Steganografi Audio: MP3 (Secure Container Injection)")
    carrier_mp3 = stego_test_dir / "carrier_audio.mp3"
    stego_mp3 = stego_test_dir / "stego_audio.mp3"
    create_dummy_mp3(carrier_mp3, duration_sec=2.0)

    res_mp3 = embed_audio(carrier_mp3, secret_text, aes_stego_key, stego_mp3)
    print(f"  * Audio MP3 Stego Dihasilkan: {Path(res_mp3['output_path']).name}")
    print(f"  * Format Digunakan          : {res_mp3['format']}")
    print(f"  * Payload Tersemat          : {res_mp3['payload_bytes']} bytes")
    assert Path(stego_mp3).exists(), "GAGAL: Berkas audio MP3 stego tidak terbuat!"

    extracted_mp3_msg = extract_audio(stego_mp3, aes_stego_key)
    print(f"  * Pesan MP3 Terekstrak      : '{extracted_mp3_msg}'")
    assert extracted_mp3_msg == secret_text, "GAGAL: Pesan hasil ekstraksi MP3 tidak cocok!"
    print("  [PASSED] Ekstraksi steganografi audio MP3 100% Cocok dan Utuh.")

    try:
        extract_audio(stego_mp3, wrong_key)
        assert False, "GAGAL: Kunci AES salah pada MP3 harus ditolak!"
    except ValueError:
        print("  [PASSED] Penolakan kunci salah pada MP3 berhasil.")

    # -------------------------------------------------------------------------
    # UJI 6: STEGANOGRAFI VIDEO MP4 (ISO BMFF FREE-BOX INJECTION)
    # -------------------------------------------------------------------------
    print("\n[UJI 6] Steganografi Video: MP4 (ISO BMFF Free-Space Box Container Injection)")
    carrier_mp4 = stego_test_dir / "carrier_video.mp4"
    stego_mp4 = stego_test_dir / "stego_video.mp4"
    create_dummy_mp4(carrier_mp4, num_frames=15, width=160, height=120)

    res_mp4 = embed_video(carrier_mp4, secret_text, aes_stego_key, stego_mp4)
    print(f"  * Video MP4 Stego Dihasilkan: {Path(res_mp4['output_path']).name}")
    print(f"  * Format Digunakan          : {res_mp4['format']}")
    print(f"  * Payload Tersemat          : {res_mp4['payload_bytes']} bytes")
    assert Path(stego_mp4).exists(), "GAGAL: Berkas video MP4 stego tidak terbuat!"

    extracted_mp4_msg = extract_video(stego_mp4, aes_stego_key)
    print(f"  * Pesan MP4 Terekstrak      : '{extracted_mp4_msg}'")
    assert extracted_mp4_msg == secret_text, "GAGAL: Pesan hasil ekstraksi MP4 tidak cocok!"
    print("  [PASSED] Ekstraksi steganografi video MP4 100% Cocok dan Utuh.")

    try:
        extract_video(stego_mp4, wrong_key)
        assert False, "GAGAL: Kunci AES salah pada MP4 harus ditolak!"
    except ValueError:
        print("  [PASSED] Penolakan kunci salah pada MP4 berhasil.")

    print("\n" + "=" * 75)
    print(" SELURUH PENGUJIAN TAHAP 5 BERHASIL 100%! STEGANOGRAFI MULTIMEDIA SIAP.")
    print("=" * 75)


if __name__ == "__main__":
    run_tests()

