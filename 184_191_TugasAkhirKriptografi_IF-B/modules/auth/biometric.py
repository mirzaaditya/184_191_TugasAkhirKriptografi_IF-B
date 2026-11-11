"""
==============================================================================
MODUL: BIOMETRIK VERIFIKASI WAJAH (OPENCV FACE VERIFICATION)
==============================================================================
Deskripsi:
Modul ini mengimplementasikan verifikasi biometrik berbasis wajah menggunakan
OpenCV. Fitur wajah dideteksi menggunakan Haar Cascade Classifier, diekstraksi,
dinormalisasi (grayscale & histogram equalization), kemudian dibandingkan
menggunakan metrik korelasi koefisien (Normalized Cross-Correlation) dan
korelasi histogram intensitas.

Alur Kerja:
1. Input: Citra wajah dari webcam (atau stream kamera Streamlit).
2. Deteksi: Lokalisasi wajah dengan Haar Cascade (haarcascade_frontalface_default).
3. Pra-proses: Pemotongan (crop) area wajah, resize standar (200x200), dan
   ekualisasi histogram untuk mereduksi pengaruh variasi pencahayaan.
4. Komparasi: Menghitung skor kemiripan (similarity score) terhadap foto
   rujukan yang tersimpan saat registrasi.
5. Verifikasi: Jika skor >= ambang batas (threshold), pengguna dinyatakan lolos.
==============================================================================
"""

import os
import re
import hashlib
from pathlib import Path
import cv2
import numpy as np
from config.settings import (
    REFERENCE_FACES_DIR,
    FACE_SIMILARITY_THRESHOLD,
    FACE_TARGET_SIZE
)

# Inisialisasi Haar Cascade Classifier bawaan OpenCV
HAAR_CASCADE_PATH = os.path.join(cv2.data.haarcascades, "haarcascade_frontalface_default.xml")
face_cascade = cv2.CascadeClassifier(HAAR_CASCADE_PATH)


def load_image(image_input) -> np.ndarray | None:
    """
    Mengonversi berbagai jenis input citra (Path, str, bytes, atau np.ndarray)
    menjadi format matriks NumPy OpenCV (BGR).
    """
    if image_input is None:
        return None
        
    if isinstance(image_input, (str, Path)):
        p = Path(image_input)
        if not p.exists():
            return None
        # cv2.imread membaca dalam format BGR
        return cv2.imread(str(p))
        
    if isinstance(image_input, bytes):
        # Decode byte stream (misal dari st.camera_input atau file upload)
        nparr = np.frombuffer(image_input, np.uint8)
        return cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
    if isinstance(image_input, np.ndarray):
        return image_input.copy()
        
    return None


def detect_and_crop_face(image_input) -> tuple[np.ndarray | None, str]:
    """
    Mendeteksi wajah pada citra dan memotong area wajah utama.
    
    Args:
        image_input: Citra (path file, bytes, atau numpy array).
        
    Returns:
        tuple[np.ndarray | None, str]: (Matriks wajah cropped ternormalisasi, pesan status)
    """
    img = load_image(image_input)
    if img is None:
        return None, "Gagal memuat citra (format tidak didukung atau file tidak ditemukan)."
        
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    
    # Deteksi wajah dengan parameter scaleFactor=1.1 dan minNeighbors=5
    faces = face_cascade.detectMultiScale(
        gray,
        scaleFactor=1.1,
        minNeighbors=5,
        minSize=(60, 60)
    )
    
    if len(faces) == 0:
        return None, "Wajah tidak terdeteksi dalam frame. Pastikan pencahayaan cukup dan wajah menghadap kamera."
        
    # Ambil wajah dengan ukuran area bounding box terbesar (wajah utama)
    faces = sorted(faces, key=lambda f: f[2] * f[3], reverse=True)
    x, y, w, h = faces[0]
    
    # Crop area wajah
    cropped = gray[y : y + h, x : x + w]
    
    # Resize ke dimensi standar (misal 200x200 pixel)
    resized = cv2.resize(cropped, FACE_TARGET_SIZE, interpolation=cv2.INTER_AREA)
    
    # Ekualisasi histogram untuk meratakan distribusi intensitas cahaya
    normalized_face = cv2.equalizeHist(resized)
    
    return normalized_face, "Wajah berhasil dideteksi dan diproses."


def compute_similarity(face1: np.ndarray, face2: np.ndarray) -> float:
    """
    Menghitung skor kemiripan antara dua wajah ternormalisasi (0.0 sampai 1.0).
    Menggabungkan Normalized Cross-Correlation (TM_CCOEFF_NORMED) dan Histogram Correlation.
    """
    if face1.shape != face2.shape:
        face2 = cv2.resize(face2, (face1.shape[1], face1.shape[0]))
        
    # 1. Metrik Template Matching (Cross-Correlation)
    res_corr = cv2.matchTemplate(face1, face2, cv2.TM_CCOEFF_NORMED)[0][0]
    # Konversi dari [-1, 1] ke [0, 1]
    score_ncc = max(0.0, float(res_corr))
    
    # 2. Metrik Histogram Correlation
    hist1 = cv2.calcHist([face1], [0], None, [64], [0, 256])
    hist2 = cv2.calcHist([face2], [0], None, [64], [0, 256])
    cv2.normalize(hist1, hist1, alpha=0, beta=1, norm_type=cv2.NORM_MINMAX)
    cv2.normalize(hist2, hist2, alpha=0, beta=1, norm_type=cv2.NORM_MINMAX)
    score_hist = max(0.0, float(cv2.compareHist(hist1, hist2, cv2.HISTCMP_CORREL)))
    
    # 3. Metrik Cosine Similarity pada vektor piksel
    vec1 = face1.flatten().astype(np.float32)
    vec2 = face2.flatten().astype(np.float32)
    norm1 = np.linalg.norm(vec1)
    norm2 = np.linalg.norm(vec2)
    if norm1 > 0 and norm2 > 0:
        score_cosine = max(0.0, float(np.dot(vec1, vec2) / (norm1 * norm2)))
    else:
        score_cosine = 0.0
        
    # Kombinasi berbobot (ensemble metric)
    final_score = (0.45 * score_ncc) + (0.35 * score_hist) + (0.20 * score_cosine)
    return round(min(1.0, max(0.0, final_score)), 4)


def get_safe_face_path(username: str) -> Path:
    """
    Menghasilkan path berkas citra rujukan yang aman pada seluruh sistem operasi
    (menghindari karakter terlarang Windows seperti * ? / \\ : < > |).
    """
    clean = username.lower().strip()
    safe_slug = re.sub(r'[^a-zA-Z0-9_\-]', '_', clean)
    user_hash = hashlib.sha256(clean.encode('utf-8')).hexdigest()[:8]
    return REFERENCE_FACES_DIR / f"{safe_slug}_{user_hash}_face.png"


def register_reference_face(username: str, image_input) -> tuple[bool, str, Path | None]:
    """
    Mendaftarkan foto rujukan biometrik wajah pengguna baru.
    
    Args:
        username (str): Username pemilik wajah.
        image_input: Citra wajah yang akan disimpan sebagai rujukan.
        
    Returns:
        tuple[bool, str, Path | None]: (Status, Pesan, Path File Tersimpan)
    """
    face_mat, msg = detect_and_crop_face(image_input)
    if face_mat is None:
        return False, f"Pendaftaran biometrik gagal: {msg}", None
        
    ref_path = get_safe_face_path(username)
    # Simpan wajah yang sudah di-crop dan dinormalisasi
    write_success = cv2.imwrite(str(ref_path), face_mat)
    if not write_success or not ref_path.exists() or ref_path.stat().st_size == 0:
        return False, f"Gagal menyimpan berkas citra rujukan biometrik ke disk ({ref_path.name}).", None
        
    return True, f"Foto rujukan biometrik wajah untuk '{username}' berhasil disimpan.", ref_path


def verify_face(
    username: str,
    live_image_input,
    stored_face_path: str | Path = None
) -> tuple[bool, str, float]:
    """
    Memverifikasi citra langsung (webcam) terhadap foto rujukan pengguna yang tersimpan.
    
    Args:
        username (str): Username yang sedang mencoba login.
        live_image_input: Citra dari kamera saat proses login.
        stored_face_path (str | Path, optional): Path rujukan yang tersimpan di basis data.
        
    Returns:
        tuple[bool, str, float]: (Status Lolos, Pesan Hasil, Skor Kemiripan 0.0-1.0)
    """
    clean = username.lower().strip()
    
    # 1. Cari path berkas rujukan (Cek path dari database -> safe path -> legacy path)
    ref_path = None
    if stored_face_path and Path(stored_face_path).exists():
        ref_path = Path(stored_face_path)
    else:
        candidate_safe = get_safe_face_path(clean)
        if candidate_safe.exists():
            ref_path = candidate_safe
        else:
            candidate_legacy = REFERENCE_FACES_DIR / f"{clean}_face.png"
            if candidate_legacy.exists():
                ref_path = candidate_legacy
                
    if not ref_path or not ref_path.exists():
        return False, f"Data biometrik rujukan untuk pengguna '{username}' belum terdaftar.", 0.0
        
    ref_face = cv2.imread(str(ref_path), cv2.IMREAD_GRAYSCALE)
    if ref_face is None:
        return False, "File rujukan biometrik rusak atau tidak dapat dibaca.", 0.0
        
    live_face, msg = detect_and_crop_face(live_image_input)
    if live_face is None:
        return False, f"Verifikasi biometrik gagal: {msg}", 0.0
        
    similarity = compute_similarity(ref_face, live_face)
    
    if similarity >= FACE_SIMILARITY_THRESHOLD:
        return (
            True,
            f"Verifikasi biometrik BERHASIL. Kecocokan wajah: {similarity * 100:.1f}% (Threshold: {FACE_SIMILARITY_THRESHOLD * 100:.0f}%).",
            similarity
        )
    else:
        return (
            False,
            f"Verifikasi biometrik DITOLAK. Wajah tidak cocok! Kemiripan: {similarity * 100:.1f}% (Minimal: {FACE_SIMILARITY_THRESHOLD * 100:.0f}%).",
            similarity
        )


def capture_frame_from_webcam(device_index: int = 0) -> np.ndarray | None:
    """
    Fungsi bantuan untuk mengambil 1 frame dari kamera fisik lokal (webcam).
    Cocok untuk pengujian skrip terminal tanpa GUI browser.
    """
    cap = cv2.VideoCapture(device_index)
    if not cap.isOpened():
        return None
        
    # Ambil beberapa frame pemanasan sensor kamera
    for _ in range(5):
        cap.read()
        
    ret, frame = cap.read()
    cap.release()
    
    if ret:
        return frame
    return None

