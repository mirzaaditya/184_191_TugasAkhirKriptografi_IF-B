"""
==============================================================================
MODUL: HARDWARE DONGLE VALIDATOR (USB SECURITY TOKEN)
==============================================================================
Deskripsi:
Modul ini bertindak sebagai gerbang fisik (hardware token) aplikasi.
Aplikasi hanya dapat dibuka jika USB flashdisk fisik terpasang dan memuat
file kunci terenkripsi (secure_dongle.key) yang memiliki tanda tangan digital
kriptografis (HMAC-SHA256) serta payload terenkripsi AES-256-GCM yang valid.

Alur Kerja:
1. Pindai drive penyimpanan removable (USB flashdisk) menggunakan psutil.
2. Cari keberadaan file `secure_dongle.key`.
3. Validasi keaslian file menggunakan HMAC-SHA256 (mencegah modifikasi data).
4. Verifikasi dan dekripsi token internal dengan AES-256-GCM.
5. Mendukung fallback ke direktori virtual untuk kemudahan pengujian.
==============================================================================
"""

import os
import json
import uuid
import datetime
import hmac
import hashlib
import re
import psutil
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from config.settings import (
    DONGLE_KEY_FILENAME,
    DONGLE_MASTER_SECRET,
    VIRTUAL_DONGLE_DIR
)


def get_removable_drives() -> list[Path]:
    """
    Memindai seluruh drive sistem untuk menemukan drive eksternal / removable (USB).
    
    Returns:
        list[Path]: Daftar path root dari drive USB yang terpasang.
    """
    usb_drives = []
    try:
        partitions = psutil.disk_partitions(all=True)
        for p in partitions:
            # Pada Windows, flashdisk umumnya ditandai dengan opsi 'removable'
            # dan biasanya bukan drive sistem C:\
            opts = p.opts.lower()
            mount = p.mountpoint
            if "removable" in opts or (p.device.upper() != "C:\\" and "cdrom" not in opts):
                drive_path = Path(mount)
                if drive_path.exists():
                    usb_drives.append(drive_path)
    except Exception:
        pass
        
    return usb_drives


def generate_dongle_key(target_path: Path, username: str, master_secret: bytes = DONGLE_MASTER_SECRET, per_user_folder: bool = False) -> Path:
    """
    Membuat file kunci digital baru (`secure_dongle.key`) pada drive USB atau direktori target.
    Kunci ini berisi metadata bertanda tangan HMAC-SHA256 dan token rahasia AES-256-GCM.
    
    Args:
        target_path (Path): Path direktori tujuan penyimpanan file kunci (misal: E:\\).
        username (str): Nama pengguna pemilik dongle.
        master_secret (bytes): Kunci rahasia master sistem.
        
    Returns:
        Path: Path lengkap file kunci yang berhasil dibuat.
    """
    target_path = Path(target_path)
    clean_username = username.strip().lower()
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{3,32}", clean_username):
        raise ValueError("Username tidak valid untuk nama folder dongle.")

    # USB bersama: simpan kunci di subfolder khusus milik user.
    storage_path = target_path / clean_username if per_user_folder else target_path
    storage_path.mkdir(parents=True, exist_ok=True)
    key_file = storage_path / DONGLE_KEY_FILENAME

    # Cegah dongle user lain tertimpa pada mode USB terpisah.
    if key_file.exists():
        try:
            with key_file.open("r", encoding="utf-8") as existing_file:
                existing_data = json.load(existing_file)
            existing_owner = str(existing_data.get("owner_username", "")).lower()
            if existing_owner and existing_owner != clean_username:
                raise FileExistsError(
                    f"Lokasi {key_file} sudah berisi dongle milik '{existing_owner}'. "
                    "Pilih USB lain atau gunakan mode USB bersama."
                )
        except json.JSONDecodeError:
            raise FileExistsError(
                f"File {key_file} tidak valid. Backup/pindahkan file tersebut dahulu."
            )
    
    # 1. Buat token unik dan metadata
    dongle_uuid = str(uuid.uuid4())
    issued_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    raw_token = f"TOKEN-AUTH-{clean_username}-{dongle_uuid}".encode("utf-8")
    
    # 2. Enkripsi token dengan AES-256-GCM
    # Gunakan SHA-256 dari master_secret untuk memastikan panjang kunci tepat 32 byte (256-bit)
    aes_key = hashlib.sha256(master_secret).digest()
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # 96-bit nonce untuk AES-GCM
    encrypted_token = aesgcm.encrypt(nonce, raw_token, None)
    
    # 3. Bentuk dictionary payload
    payload = {
        "dongle_uuid": dongle_uuid,
        "owner_username": clean_username,
        "issued_at": issued_at,
        "nonce_hex": nonce.hex(),
        "encrypted_token_hex": encrypted_token.hex()
    }
    
    # 4. Beri tanda tangan digital HMAC-SHA256 untuk menjaga integritas file
    canonical_data = f"{dongle_uuid}|{clean_username}|{issued_at}|{payload['nonce_hex']}|{payload['encrypted_token_hex']}"
    signature = hmac.new(master_secret, canonical_data.encode("utf-8"), hashlib.sha256).hexdigest()
    payload["signature"] = signature
    
    # 5. Tulis ke file JSON
    with open(key_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=4)
        
    return key_file


def verify_dongle(
    username: str = None,
    master_secret: bytes = DONGLE_MASTER_SECRET,
    custom_search_paths: list[Path] = None,
    restrict_to_custom_paths: bool = False
) -> tuple[bool, str, dict | None]:
    """
    Mendukung dongle terpisah (<USB>/secure_dongle.key) dan USB bersama
    (<USB>/<username>/secure_dongle.key), sekaligus mempertahankan layout lama.
    """
    clean_username = username.strip().lower() if username else None
    # Jika UI memilih drive tertentu, verifikasi hanya lokasi tersebut.
    # Hindari token dari drive lain/virtual terpilih secara tidak sengaja.
    if restrict_to_custom_paths:
        roots = [Path(p) for p in (custom_search_paths or [])]
    else:
        roots = [Path(p) for p in (custom_search_paths or [])]
        roots.extend(get_removable_drives())
        roots.append(Path(VIRTUAL_DONGLE_DIR))

    unique_roots, seen_roots = [], set()
    for root in roots:
        root = Path(root)
        marker = str(root.resolve()) if root.exists() else str(root.absolute())
        if marker not in seen_roots:
            seen_roots.add(marker)
            unique_roots.append(root)

    candidates = []
    for root in unique_roots:
        candidates.append(root / DONGLE_KEY_FILENAME)  # USB terpisah / format lama
        if clean_username:
            candidates.append(root / clean_username / DONGLE_KEY_FILENAME)
            candidates.append(root / "dongles" / clean_username / DONGLE_KEY_FILENAME)

    candidate_files, seen_files = [], set()
    for candidate in candidates:
        marker = str(candidate)
        if marker not in seen_files:
            seen_files.add(marker)
            if candidate.is_file():
                candidate_files.append(candidate)

    if not candidate_files:
        return False, (
            "Dongle tidak ditemukan. Pastikan USB terpasang dan file "
            f"{DONGLE_KEY_FILENAME} berada di root atau folder username."
        ), None

    mismatch_users, invalid_messages = [], []
    for key_file in candidate_files:
        try:
            with key_file.open("r", encoding="utf-8") as f:
                data = json.load(f)

            required = [
                "dongle_uuid", "owner_username", "issued_at",
                "nonce_hex", "encrypted_token_hex", "signature"
            ]
            if not isinstance(data, dict) or not all(k in data for k in required):
                invalid_messages.append(f"Struktur file tidak lengkap: {key_file}")
                continue

            owner = str(data["owner_username"]).strip().lower()
            canonical_data = (
                f"{data['dongle_uuid']}|{data['owner_username']}|{data['issued_at']}|"
                f"{data['nonce_hex']}|{data['encrypted_token_hex']}"
            )
            expected_sig = hmac.new(
                master_secret, canonical_data.encode("utf-8"), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(expected_sig, str(data["signature"])):
                invalid_messages.append(f"Signature tidak valid: {key_file}")
                continue

            try:
                aes_key = hashlib.sha256(master_secret).digest()
                aesgcm = AESGCM(aes_key)
                nonce = bytes.fromhex(data["nonce_hex"])
                encrypted_token = bytes.fromhex(data["encrypted_token_hex"])
                decrypted_token = aesgcm.decrypt(nonce, encrypted_token, None).decode("utf-8")
            except Exception:
                invalid_messages.append(f"Dekripsi token gagal: {key_file}")
                continue

            if not decrypted_token.startswith(f"TOKEN-AUTH-{owner}-"):
                invalid_messages.append(f"Token tidak cocok dengan pemilik: {key_file}")
                continue

            if clean_username and owner != clean_username:
                mismatch_users.append(owner)
                continue

            data["decrypted_token"] = decrypted_token
            data["dongle_key_path"] = str(key_file)
            return True, f"Dongle valid untuk user '{owner}' ({key_file}).", data

        except Exception as e:
            invalid_messages.append(f"{key_file}: {e}")

    if mismatch_users:
        return False, (
            f"Dongle untuk user '{clean_username}' tidak ditemukan. "
            f"Pemilik dongle lain terdeteksi: {', '.join(sorted(set(mismatch_users)))}."
        ), None

    detail = "; ".join(invalid_messages[:3])
    return False, "Tidak ditemukan dongle valid." + (f" Detail: {detail}" if detail else ""), None
