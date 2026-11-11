"""
==============================================================================
MODUL: STEGANOGRAFI VIDEO (MP4 CONTAINER FREE-BOX & AVI LOSSLESS LSB)
==============================================================================
Deskripsi:
Modul ini mengamankan pesan rahasia dengan menyisipkan ciphertext AES-256-GCM ke dalam
media video digital dengan 2 pendekatan:

1. Format MP4 (ISO BMFF Free-Space Box Container Injection):
   Menyisipkan payload terenkripsi AES-256-GCM ke dalam atom/box 'free' standar
   ISO Base Media File Format (ISO/IEC 14496-12). Format ini 100% kompatibel dengan
   pemutar video modern, browser, dan HTML5 <video> tanpa merusak kompresi H.264/MPEG-4.

2. Format AVI Lossless (FFV1/HuffYUV LSB Frame):
   Memecah frame video individual menggunakan OpenCV, menyisipkan ciphertext ke dalam
   bit LSB piksel, lalu merekonstruksi video menggunakan codec bit-exact lossless FFV1.
==============================================================================
"""

import cv2
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

MP4_STEGO_MARKER = b"STEGOMP4"


def create_dummy_mp4(
    output_path: str | Path,
    num_frames: int = 20,
    width: int = 160,
    height: int = 120,
    fps: float = 10.0
) -> Path:
    """
    Membuat video sintetis berformat MP4 menggunakan codec mp4v OpenCV
    yang dapat langsung diputar di browser dan aplikasi pemutar video.
    """
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    fourcc = cv2.VideoWriter_fourcc(*"mp4v")
    writer = cv2.VideoWriter(str(p), fourcc, fps, (width, height))
    if not writer.isOpened():
        fourcc = cv2.VideoWriter_fourcc(*"avc1")
        writer = cv2.VideoWriter(str(p), fourcc, fps, (width, height))

    for i in range(num_frames):
        frame = np.zeros((height, width, 3), dtype=np.uint8)
        frame[:, :, 0] = (i * 12) % 256                         # Blue
        frame[:, :, 1] = np.linspace(50, 200, width, dtype=np.uint8)  # Green
        frame[:, :, 2] = 128                                    # Red
        cv2.circle(frame, ((i * 8) % width, height // 2), 15, (255, 255, 255), -1)
        writer.write(frame)

    writer.release()
    return p


def create_dummy_video(
    output_path: str | Path,
    num_frames: int = 20,
    width: int = 160,
    height: int = 120,
    fps: float = 10.0
) -> Path:
    """
    Membuat video sintetis untuk pengujian steganografi.
    Jika ekstensi .mp4, menghasilkan MP4. Jika .avi, menghasilkan Lossless FFV1 AVI.
    """
    p = Path(output_path)
    if p.suffix.lower() == ".mp4":
        return create_dummy_mp4(output_path, num_frames, width, height, fps)

    p.parent.mkdir(parents=True, exist_ok=True)
    fourcc = cv2.VideoWriter_fourcc(*"FFV1")
    writer = cv2.VideoWriter(str(p), fourcc, fps, (width, height))
    
    if not writer.isOpened():
        fourcc = cv2.VideoWriter_fourcc(*"HFYU")
        writer = cv2.VideoWriter(str(p), fourcc, fps, (width, height))
        
    for i in range(num_frames):
        frame = np.zeros((height, width, 3), dtype=np.uint8)
        frame[:, :, 0] = (i * 12) % 256
        frame[:, :, 1] = np.linspace(50, 200, width, dtype=np.uint8)
        frame[:, :, 2] = 128
        cv2.circle(frame, ((i * 8) % width, height // 2), 15, (255, 255, 255), -1)
        writer.write(frame)
        
    writer.release()
    return p


def embed_video(
    carrier_video_path: str | Path,
    secret_message: str | bytes,
    aes_key: str | bytes,
    output_video_path: str | Path
) -> dict:
    """
    Menyisipkan pesan rahasia terenkripsi AES-256-GCM ke dalam video.
    Mendukung format MP4 (ISO BMFF Free-Space Box) dan AVI (Lossless FFV1 LSB).
    
    Args:
        carrier_video_path: Path video pembawa asli (.mp4 atau .avi).
        secret_message: Pesan rahasia yang akan disembunyikan.
        aes_key: Kunci enkripsi AES-256.
        output_video_path: Path tujuan video stego.
        
    Returns:
        dict: Informasi statistik penyisipan video.
    """
    src_path = Path(carrier_video_path)
    if not src_path.exists():
        raise FileNotFoundError(f"Berkas video pembawa '{src_path}' tidak ditemukan.")
        
    dst_path = Path(output_video_path)
    dst_path.parent.mkdir(parents=True, exist_ok=True)

    is_mp4 = (src_path.suffix.lower() == ".mp4" or dst_path.suffix.lower() == ".mp4")

    # 1. Enkripsi pesan dengan AES-256-GCM dan kemas payload
    payload_bytes = prepare_encrypted_payload(secret_message, aes_key)

    if is_mp4:
        # -------------------------------------------------------------
        # METODE MP4: ISO BMFF Free-Space Box Container Injection
        # -------------------------------------------------------------
        carrier_bytes = src_path.read_bytes()
        if not carrier_bytes:
            raise ValueError(f"Berkas video MP4 '{src_path}' kosong.")

        # Bersihkan box stego lama jika ada
        idx = carrier_bytes.rfind(MP4_STEGO_MARKER)
        if idx != -1 and idx + 12 <= len(carrier_bytes):
            p_len = struct.unpack(">I", carrier_bytes[idx+8:idx+12])[0]
            box_start = idx - p_len - 8
            if box_start >= 0 and carrier_bytes[box_start+4:box_start+8] == b"free":
                carrier_bytes = carrier_bytes[:box_start]

        # Buat ISO BMFF 'free' box: [4B size] + [4B 'free'] + [payload] + [8B marker] + [4B payload len]
        box_data = payload_bytes + MP4_STEGO_MARKER + struct.pack(">I", len(payload_bytes))
        free_box_size = 8 + len(box_data)
        free_box = struct.pack(">I", free_box_size) + b"free" + box_data

        stego_mp4_bytes = carrier_bytes + free_box
        dst_path.write_bytes(stego_mp4_bytes)

        return {
            "status": "success",
            "format": "MP4 (ISO BMFF Free-Space Box Injection)",
            "output_path": str(dst_path),
            "payload_bytes": len(payload_bytes),
            "embedded_bits": len(payload_bytes) * 8,
            "carrier_size_bytes": len(carrier_bytes),
            "output_size_bytes": len(stego_mp4_bytes)
        }

    # -----------------------------------------------------------------
    # METODE AVI: LSB pada Frame Video dengan Codec Lossless FFV1
    # -----------------------------------------------------------------
    if dst_path.suffix.lower() != ".avi":
        dst_path = dst_path.with_suffix(".avi")
        
    payload_bits = bytes_to_bits(payload_bytes)
    total_bits_needed = len(payload_bits)
    
    cap = cv2.VideoCapture(str(src_path))
    if not cap.isOpened():
        raise ValueError(f"Gagal membuka berkas video '{src_path}'.")
        
    fps = cap.get(cv2.CAP_PROP_FPS) or 10.0
    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    
    frames = []
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        frames.append(frame)
    cap.release()
    
    total_frames = len(frames)
    if total_frames == 0:
        raise ValueError("Video pembawa tidak memiliki frame yang valid (0 frame).")
        
    total_available_bits = total_frames * height * width * 3
    
    if total_bits_needed > total_available_bits:
        raise ValueError(
            f"Kapasitas video tidak cukup! Dibutuhkan {total_bits_needed} bits ({len(payload_bytes)} bytes), "
            f"tetapi kapasitas maksimal video hanya {total_available_bits} bits ({total_available_bits // 8} bytes)."
        )
        
    bits_embedded = 0
    modified_frames = []
    
    for frame in frames:
        if bits_embedded < total_bits_needed:
            orig_shape = frame.shape
            flat_frame = frame.flatten()
            bits_left = total_bits_needed - bits_embedded
            bits_this_frame = min(bits_left, flat_frame.size)
            
            chunk_bits = np.array(payload_bits[bits_embedded : bits_embedded + bits_this_frame], dtype=np.uint8)
            flat_frame[:bits_this_frame] = (flat_frame[:bits_this_frame] & 0xFE) | chunk_bits
            
            modified_frames.append(flat_frame.reshape(orig_shape))
            bits_embedded += bits_this_frame
        else:
            modified_frames.append(frame)
            
    fourcc = cv2.VideoWriter_fourcc(*"FFV1")
    writer = cv2.VideoWriter(str(dst_path), fourcc, fps, (width, height))
    if not writer.isOpened():
        fourcc = cv2.VideoWriter_fourcc(*"HFYU")
        writer = cv2.VideoWriter(str(dst_path), fourcc, fps, (width, height))
        
    for f in modified_frames:
        writer.write(f)
    writer.release()
    
    usage_pct = (total_bits_needed / total_available_bits) * 100
    
    return {
        "status": "success",
        "format": "AVI Lossless (FFV1 LSB)",
        "output_path": str(dst_path),
        "payload_bytes": len(payload_bytes),
        "embedded_bits": total_bits_needed,
        "total_frames": total_frames,
        "codec": "FFV1 (Lossless)",
        "capacity_usage_percent": round(usage_pct, 2),
        "resolution": f"{width}x{height} px @ {fps} fps"
    }


def extract_video(
    stego_video_path: str | Path,
    aes_key: str | bytes
) -> str:
    """
    Mengekstrak bit LSB atau box container dari berkas video (MP4 atau AVI)
    dan mendekripsi pesan rahasia dengan AES-256-GCM.
    
    Args:
        stego_video_path: Path berkas video stego (.mp4 atau .avi).
        aes_key: Kunci dekripsi AES-256.
        
    Returns:
        str: Pesan rahasia asli hasil ekstraksi dan dekripsi.
    """
    path = Path(stego_video_path)
    if not path.exists():
        raise FileNotFoundError(f"Berkas video stego '{path}' tidak ditemukan.")

    data = path.read_bytes()

    # 1. Cek apakah berkas memuat box MP4 Stego Marker
    idx = data.rfind(MP4_STEGO_MARKER)
    if idx != -1 and idx + 12 <= len(data):
        p_len = struct.unpack(">I", data[idx+8:idx+12])[0]
        if 0 < p_len <= idx:
            payload = data[idx - p_len : idx]
            return decrypt_extracted_payload(payload, aes_key)

    # 2. Cek apakah ada header SMSG langsung di file
    idx_smsg = data.rfind(b"SMSG")
    if idx_smsg != -1 and idx_smsg + HEADER_SIZE_BYTES <= len(data):
        payload_len = struct.unpack(">I", data[idx_smsg+4:idx_smsg+8])[0]
        total_req = HEADER_SIZE_BYTES + payload_len
        if idx_smsg + total_req <= len(data):
            try:
                return decrypt_extracted_payload(data[idx_smsg:idx_smsg+total_req], aes_key)
            except ValueError:
                pass

    # 3. Jika video adalah AVI, gunakan ekstraksi LSB frame OpenCV
    cap = cv2.VideoCapture(str(path))
    if not cap.isOpened():
        raise ValueError(f"Gagal membuka berkas video stego '{path}'.")
        
    collected_bits = []
    header_unpacked = False
    total_bits_expected = None
    
    while True:
        ret, frame = cap.read()
        if not ret:
            break
            
        flat_frame = frame.flatten()
        frame_lsb = (flat_frame & 1).tolist()
        collected_bits.extend(frame_lsb)
        
        if not header_unpacked and len(collected_bits) >= 64:
            header_bytes = bits_to_bytes(collected_bits[:64])
            if header_bytes[:4] != b"SMSG":
                cap.release()
                raise ValueError("Video ini tidak memuat pesan steganografi yang valid (Header SMSG tidak ditemukan).")
                
            payload_len = struct.unpack(">I", header_bytes[4:8])[0]
            total_bytes = HEADER_SIZE_BYTES + payload_len
            total_bits_expected = total_bytes * 8
            header_unpacked = True
            
        if header_unpacked and len(collected_bits) >= total_bits_expected:
            break
            
    cap.release()
    
    if not header_unpacked or (total_bits_expected and len(collected_bits) < total_bits_expected):
        raise ValueError("Bit steganografi pada video tidak lengkap atau terpotong sebelum payload selesai.")
        
    payload_bits = collected_bits[:total_bits_expected]
    all_bytes = bits_to_bytes(payload_bits)
    
    return decrypt_extracted_payload(all_bytes, aes_key)


