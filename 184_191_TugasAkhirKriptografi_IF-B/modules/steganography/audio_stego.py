"""
==============================================================================
MODUL: STEGANOGRAFI AUDIO (MP3 CONTAINER/METADATA & WAV LSB)
==============================================================================
Deskripsi:
Modul ini menyembunyikan pesan rahasia yang telah dienkripsi AES-256-GCM ke dalam
media audio digital dengan 2 pendekatan:

1. Format MP3 (Secure Container / Metadata Injection):
   Menyisipkan payload terenkripsi AES-256-GCM ke dalam kontainer audio MP3
   menggunakan struktur trailer/metadata aman tanpa merusak kompresi audio lossy.
   Audio MP3 tetap dapat diputar normal di pemutar audio apa pun dan di browser.

2. Format WAV (PCM Uncompressed LSB):
   Menyisipkan bit terenkripsi ke dalam Least Significant Bit (LSB) amplitudo
   sampel 16-bit PCM tanpa degradasi audio.
==============================================================================
"""

import wave
import struct
import numpy as np
from pathlib import Path
from modules.steganography.stego_common import (
    bytes_to_bits,
    bits_to_bytes,
    prepare_encrypted_payload,
    decrypt_extracted_payload,
    HEADER_SIZE_BYTES
)

MP3_STEGO_MARKER = b"STEGOMP3"


def create_dummy_mp3(output_path: str | Path, duration_sec: float = 3.0) -> Path:
    """
    Membuat berkas audio MP3 sintetis yang valid dan dapat diputar
    untuk keperluan pengujian dan demonstrasi steganografi.
    Menggunakan frame MPEG-1 Layer III (128 kbps, 44100 Hz, Joint Stereo).
    """
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    # Frame header MPEG-1 Layer III: 128 kbps, 44.1 kHz, Joint Stereo
    # Frame size = 144 * 128000 / 44100 = 417 bytes per frame (~26.12 ms/frame)
    frame_header = bytes([0xFF, 0xFB, 0x90, 0x64])
    silent_frame = frame_header + bytes(413)

    num_frames = max(10, int(duration_sec * 38.28))
    mp3_data = silent_frame * num_frames
    p.write_bytes(mp3_data)
    return p


def create_dummy_wav(output_path: str | Path, duration_sec: float = 3.0, sample_rate: int = 44100) -> Path:
    """
    Membuat berkas audio WAV sintetis (gelombang sinus 440 Hz / Nada A)
    untuk keperluan pengujian dan demonstrasi steganografi.
    """
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    
    total_samples = int(duration_sec * sample_rate)
    t = np.linspace(0, duration_sec, total_samples, endpoint=False)
    # Nada A4 (440 Hz) dengan amplitudo nyaman
    audio_wave = (np.sin(2 * np.pi * 440.0 * t) * 16000).astype(np.int16)
    
    with wave.open(str(p), "wb") as wf:
        wf.setnchannels(1)       # Mono
        wf.setsampwidth(2)       # 16-bit PCM (2 bytes per sample)
        wf.setframerate(sample_rate)
        wf.writeframes(audio_wave.tobytes())
        
    return p


def embed_audio(
    carrier_audio_path: str | Path,
    secret_message: str | bytes,
    aes_key: str | bytes,
    output_audio_path: str | Path
) -> dict:
    """
    Menyisipkan pesan rahasia terenkripsi AES-256-GCM ke dalam berkas audio.
    Mendukung format MP3 (Secure Container Injection) dan WAV (LSB Sampel).
    
    Args:
        carrier_audio_path: Path berkas audio pembawa asli (.mp3 atau .wav).
        secret_message: Pesan rahasia yang akan disisipkan.
        aes_key: Kunci enkripsi AES-256.
        output_audio_path: Path tujuan penyimpanan audio stego.
        
    Returns:
        dict: Informasi teknis steganografi audio.
    """
    src_path = Path(carrier_audio_path)
    if not src_path.exists():
        raise FileNotFoundError(f"Berkas audio '{src_path}' tidak ditemukan.")
        
    dst_path = Path(output_audio_path)
    dst_path.parent.mkdir(parents=True, exist_ok=True)

    is_mp3 = (src_path.suffix.lower() == ".mp3" or dst_path.suffix.lower() == ".mp3")

    # 1. Enkripsi pesan dengan AES-256-GCM dan siapkan payload
    payload_bytes = prepare_encrypted_payload(secret_message, aes_key)

    if is_mp3:
        # -------------------------------------------------------------
        # METODE MP3: Secure Container Injection
        # -------------------------------------------------------------
        carrier_bytes = src_path.read_bytes()
        if not carrier_bytes:
            raise ValueError(f"Berkas audio MP3 '{src_path}' kosong.")

        # Bersihkan trailer stego lama jika ada
        if len(carrier_bytes) >= 12 and carrier_bytes[-12:-4] == MP3_STEGO_MARKER:
            old_len = struct.unpack(">I", carrier_bytes[-4:])[0]
            if len(carrier_bytes) >= 12 + old_len:
                carrier_bytes = carrier_bytes[:-(12 + old_len)]

        trailer = payload_bytes + MP3_STEGO_MARKER + struct.pack(">I", len(payload_bytes))
        stego_mp3_bytes = carrier_bytes + trailer
        dst_path.write_bytes(stego_mp3_bytes)

        return {
            "status": "success",
            "format": "MP3 (Secure Container/Metadata Injection)",
            "output_path": str(dst_path),
            "payload_bytes": len(payload_bytes),
            "embedded_bits": len(payload_bytes) * 8,
            "carrier_size_bytes": len(carrier_bytes),
            "output_size_bytes": len(stego_mp3_bytes)
        }

    # -----------------------------------------------------------------
    # METODE WAV: LSB pada Sampel PCM 16-bit
    # -----------------------------------------------------------------
    payload_bits = bytes_to_bits(payload_bytes)
    total_bits_needed = len(payload_bits)
    
    with wave.open(str(src_path), "rb") as wf:
        n_channels = wf.getnchannels()
        samp_width = wf.getsampwidth()
        frame_rate = wf.getframerate()
        n_frames = wf.getnframes()
        raw_frames = wf.readframes(n_frames)
        
    if samp_width != 2:
        raise ValueError(f"Saat ini modul mendukung WAV 16-bit PCM (samp_width=2), berkas memiliki samp_width={samp_width}.")
        
    samples = np.frombuffer(raw_frames, dtype=np.int16).copy()
    total_available_bits = len(samples)
    
    if total_bits_needed > total_available_bits:
        raise ValueError(
            f"Kapasitas audio WAV tidak cukup! Dibutuhkan {total_bits_needed} bits ({len(payload_bytes)} bytes), "
            f"tetapi kapasitas sampel audio hanya {total_available_bits} bits ({total_available_bits // 8} bytes)."
        )
        
    bits_np = np.array(payload_bits, dtype=np.int16)
    samples[:total_bits_needed] = (samples[:total_bits_needed] & ~1) | bits_np
    
    with wave.open(str(dst_path), "wb") as out_wf:
        out_wf.setnchannels(n_channels)
        out_wf.setsampwidth(samp_width)
        out_wf.setframerate(frame_rate)
        out_wf.writeframes(samples.tobytes())
        
    usage_pct = (total_bits_needed / total_available_bits) * 100
    
    return {
        "status": "success",
        "format": "WAV 16-bit PCM (LSB Replacement)",
        "output_path": str(dst_path),
        "payload_bytes": len(payload_bytes),
        "embedded_bits": total_bits_needed,
        "carrier_samples": total_available_bits,
        "capacity_usage_percent": round(usage_pct, 2),
        "duration_sec": round(n_frames / frame_rate, 2),
        "sample_rate": frame_rate
    }


def extract_audio(
    stego_audio_path: str | Path,
    aes_key: str | bytes
) -> str:
    """
    Mengekstrak pesan rahasia dari berkas audio (MP3 atau WAV) dan mendekripsi dengan AES-256-GCM.
    
    Args:
        stego_audio_path: Path berkas audio stego (.mp3 atau .wav).
        aes_key: Kunci dekripsi AES-256.
        
    Returns:
        str: Pesan rahasia asli hasil ekstraksi dan dekripsi.
    """
    path = Path(stego_audio_path)
    if not path.exists():
        raise FileNotFoundError(f"Berkas audio stego '{path}' tidak ditemukan.")

    data = path.read_bytes()

    # 1. Cek apakah berkas memiliki marker MP3 Stego
    idx = data.rfind(MP3_STEGO_MARKER)
    if idx != -1 and idx + 12 <= len(data):
        p_len = struct.unpack(">I", data[idx+8:idx+12])[0]
        if 0 < p_len <= idx:
            payload = data[idx - p_len : idx]
            return decrypt_extracted_payload(payload, aes_key)

    # 2. Cek apakah berkas memuat header SMSG langsung di container
    idx_smsg = data.rfind(b"SMSG")
    if idx_smsg != -1 and idx_smsg + HEADER_SIZE_BYTES <= len(data):
        payload_len = struct.unpack(">I", data[idx_smsg+4:idx_smsg+8])[0]
        total_req = HEADER_SIZE_BYTES + payload_len
        if idx_smsg + total_req <= len(data):
            try:
                return decrypt_extracted_payload(data[idx_smsg:idx_smsg+total_req], aes_key)
            except ValueError:
                pass

    # 3. Jika berkas adalah WAV, gunakan ekstraksi LSB sampel
    if path.suffix.lower() == ".wav" or data[:4] == b"RIFF":
        try:
            with wave.open(str(path), "rb") as wf:
                samp_width = wf.getsampwidth()
                n_frames = wf.getnframes()
                raw_frames = wf.readframes(n_frames)
                
            if samp_width == 2 and len(raw_frames) >= 64 * 2:
                samples = np.frombuffer(raw_frames, dtype=np.int16)
                header_bits = (samples[:64] & 1).tolist()
                header_bytes = bits_to_bytes(header_bits)
                
                if len(header_bytes) >= HEADER_SIZE_BYTES and header_bytes[:4] == b"SMSG":
                    payload_len = struct.unpack(">I", header_bytes[4:8])[0]
                    total_bytes = HEADER_SIZE_BYTES + payload_len
                    total_bits = total_bytes * 8
                    
                    if total_bits <= len(samples):
                        all_bits = (samples[:total_bits] & 1).tolist()
                        all_bytes = bits_to_bytes(all_bits)
                        return decrypt_extracted_payload(all_bytes, aes_key)
        except Exception:
            pass

    raise ValueError("Audio ini tidak memuat pesan steganografi yang valid (Marker SMSG/STEGOMP3 tidak ditemukan).")


