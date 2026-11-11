"""
==============================================================================
APLIKASI SECURE MESSENGER (STREAMLIT GUI INTEGRATED SYSTEM)
==============================================================================
Mata Kuliah: Kriptografi
Fitur Terintegrasi Lengkap:
1. Otentikasi 3-Faktor: Hardware Dongle USB + Wajah OpenCV + Password PBKDF2
2. Super Enkripsi Pesan Teks: Vigenère Cipher (Klasik) + AES-256-GCM (Modern)
3. Enkripsi Berkas Biner: ChaCha20-Poly1305 (AEAD Stream Cipher)
4. Basis Data Terenkripsi: SQLite Data-at-Rest Protection (AES-256-GCM Field-Level)
5. Steganografi Multimedia: Gambar PNG, Audio WAV, dan Video Lossless (FFV1)
6. Blockchain Audit Trail: Buku Besar SHA-256 dengan Konsensus Proof-of-Work
==============================================================================
"""

import os
import io
import time
import json
import base64
from pathlib import Path
import streamlit as st
import numpy as np
from PIL import Image

# Import Modul Sistem
from config.settings import (
    DATA_DIR,
    VIRTUAL_DONGLE_DIR,
    DONGLE_KEY_FILENAME,
    BLOCKCHAIN_LEDGER_PATH
)
from modules.auth.hasher import hash_password, verify_password
from modules.auth.dongle import get_removable_drives, generate_dongle_key, verify_dongle
from modules.auth.biometric import detect_and_crop_face, register_reference_face, verify_face
from modules.auth.auth_manager import register_user, authenticate_user, delete_user_account
from modules.cryptography.super_encryption import super_encrypt, super_decrypt
from modules.cryptography.file_cipher import encrypt_file_bytes, decrypt_file_bytes
from modules.database.secure_db import SecureDatabase
from modules.steganography.image_stego import embed_image, extract_image
from modules.steganography.audio_stego import embed_audio, extract_audio, create_dummy_wav, create_dummy_mp3
from modules.steganography.video_stego import embed_video, extract_video, create_dummy_video, create_dummy_mp4
from modules.blockchain.chain import Blockchain

# =============================================================================
# KONFIGURASI HALAMAN STREAMLIT
# =============================================================================
st.set_page_config(
    page_title="Secure Messenger | Tugas Akhir Kriptografi",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Inisialisasi Database dan Blockchain (Singleton session)
if "db" not in st.session_state:
    st.session_state.db = SecureDatabase()
if "blockchain" not in st.session_state:
    st.session_state.blockchain = Blockchain()
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "auth_audit_details" not in st.session_state:
    st.session_state.auth_audit_details = {}


# =============================================================================
# CUSTOM STYLING CSS
# =============================================================================
st.markdown("""
<style>
    .main-title {
        font-size: 2.2rem;
        font-weight: 800;
        color: #1E3A8A;
        margin-bottom: 0px;
    }
    .sub-title {
        font-size: 1.05rem;
        color: #4B5563;
        margin-bottom: 25px;
    }
    .security-badge {
        background-color: #ECFDF5;
        border: 1px solid #10B981;
        color: #065F46;
        padding: 4px 10px;
        border-radius: 8px;
        font-size: 0.85rem;
        font-weight: 600;
        display: inline-block;
        margin-bottom: 10px;
    }
    .crypto-card {
        background-color: #F8FAFC;
        border: 1px solid #E2E8F0;
        border-radius: 10px;
        padding: 16px;
        margin-bottom: 15px;
    }
    .chat-bubble-sent {
        background-color: #DCF8C6;
        border-radius: 10px;
        padding: 10px 14px;
        margin-bottom: 8px;
        border-left: 4px solid #34D399;
    }
    .chat-bubble-recv {
        background-color: #F3F4F6;
        border-radius: 10px;
        padding: 10px 14px;
        margin-bottom: 8px;
        border-left: 4px solid #60A5FA;
    }
    .block-card {
        background-color: #FFFFFF;
        border: 1px solid #CBD5E1;
        border-radius: 10px;
        padding: 14px;
        margin-bottom: 12px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
</style>
""", unsafe_allow_html=True)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
def get_available_dongle_paths():
    """Mendeteksi USB flashdisk fisik dan menyertakan folder virtual fallback."""
    paths = []
    removable = get_removable_drives()
    for r in removable:
        paths.append(str(r))
    paths.append(str(VIRTUAL_DONGLE_DIR))
    return paths


# =============================================================================
# TAMPILAN JIKA BELUM LOGIN (LOGIN & REGISTRASI 3FA)
# =============================================================================
def render_auth_view():
    # Tampilkan notifikasi setelah sesi dikunci akibat dongle terputus/tidak valid.
    dongle_notice = st.session_state.pop("dongle_disconnect_notice", None)
    if dongle_notice:
        st.error(dongle_notice)

    st.markdown('<div class="main-title">🛡️ Secure Messenger</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-title">Aplikasi Pesan Rahasia Multi-Akun dengan Keamanan Berlapis (Defense-in-Depth)</div>', unsafe_allow_html=True)
    
    col_info1, col_info2, col_info3 = st.columns(3)
    with col_info1:
        st.info("🔑 **Faktor 1: Dongle USB**\nMemvalidasi tanda tangan HMAC-SHA256 & token terenkripsi AES-256 pada flashdisk.")
    with col_info2:
        st.info("👤 **Faktor 2: Biometrik Wajah**\nVerifikasi kecocokan wajah langsung menggunakan OpenCV Haar Cascade & Normalisasi.")
    with col_info3:
        st.info("🔒 **Faktor 3: Kata Sandi PBKDF2**\nPengamanan kredensial dengan 100.000 iterasi PBKDF2-HMAC-SHA256 + 128-bit Salt.")

    st.write("---")
    
    tab_login, tab_register, tab_dongle_tool, tab_manage_users = st.tabs([
        "🔐 Masuk (3-Factor Login)",
        "📝 Pendaftaran Pengguna Baru",
        "🛠️ Generator Kunci Dongle USB",
        "🗑️ Kelola / Hapus Akun"
    ])

    # -------------------------------------------------------------------------
    # TAB 1: LOGIN 3-FAKTOR
    # -------------------------------------------------------------------------
    with tab_login:
        st.subheader("Login Akun dengan 3 Faktor Keamanan")
        
        users_list = st.session_state.db.list_users()
        if not users_list:
            st.warning("Belum ada pengguna terdaftar. Silakan buka tab **Pendaftaran Pengguna Baru** terlebih dahulu.")
        else:
            col_l1, col_l2 = st.columns(2)
            
            with col_l1:
                selected_user = st.selectbox("Pilih Akun Pengguna", options=users_list, index=0)
                input_password = st.text_input("Kata Sandi Master", type="password", key="login_pwd")
                
                # Opsi Dongle USB
                dongle_options = get_available_dongle_paths()
                selected_dongle = st.selectbox(
                    "Pilih Lokasi USB Flashdisk / Dongle",
                    options=dongle_options,
                    format_func=lambda p: f"💾 Flashdisk Fisik ({p})" if p != str(VIRTUAL_DONGLE_DIR) else f"📁 Virtual Dongle ({p})",
                    help="Pastikan flashdisk terpasang dan memiliki berkas secure_dongle.key"
                )
                
            with col_l2:
                st.write("**Verifikasi Wajah Biometrik (OpenCV):**")
                bio_input_method = st.radio(
                    "Sumber Kamera Biometrik",
                    ["Ambil dari Kamera Langsung (Webcam)", "Unggah Foto Wajah"],
                    horizontal=True
                )
                
                live_face_bytes = None
                if bio_input_method == "Ambil dari Kamera Langsung (Webcam)":
                    cam_capture = st.camera_input("Arahkan wajah ke kamera untuk verifikasi")
                    if cam_capture is not None:
                        live_face_bytes = cam_capture.getvalue()
                else:
                    uploaded_face = st.file_uploader("Unggah foto wajah untuk verifikasi", type=["jpg", "jpeg", "png"], key="login_face_upload")
                    if uploaded_face is not None:
                        live_face_bytes = uploaded_face.getvalue()
                        st.image(live_face_bytes, width=150, caption="Pratinjau Foto Login")
                        
            if st.button("🚀 Verifikasi 3FA & Masuk ke Aplikasi", type="primary", use_container_width=True):
                if not input_password:
                    st.error("Kata sandi tidak boleh kosong!")
                elif live_face_bytes is None:
                    st.error("Wajib mengambil atau mengunggah citra wajah untuk verifikasi biometrik!")
                else:
                    with st.spinner("Menjalankan validasi 3-Faktor (Dongle + Wajah + PBKDF2)..."):
                        success, message, report = authenticate_user(
                            username=selected_user,
                            password=input_password,
                            face_image_input=live_face_bytes,
                            custom_dongle_paths=[Path(selected_dongle)]
                        )
                        
                        # Catat ke Blockchain Audit Trail
                        audit_status = "SUCCESS" if success else "FAILED"
                        st.session_state.blockchain.record_login_audit(
                            actor=selected_user,
                            status=audit_status,
                            factor_details={
                                "dongle": report.get("dongle_status", False),
                                "biometric": report.get("biometric_status", False),
                                "password": report.get("password_status", False),
                                "message": message
                            }
                        )
                        
                        # Catat ke Database Audit Logs
                        st.session_state.db.store_audit_log(
                            event_type=f"LOGIN_{audit_status}",
                            actor=selected_user,
                            details=f"Hasil 3FA: Dongle={report.get('dongle_status')}, Bio={report.get('biometric_status')}, Pwd={report.get('password_status')}"
                        )
                        
                        if success:
                            # Simpan identitas dongle yang benar-benar dipakai saat login.
                            # Pemantauan berikutnya hanya menerima token yang sama dari drive ini.
                            dongle_ok, _, dongle_payload = verify_dongle(
                                username=selected_user,
                                custom_search_paths=[Path(selected_dongle)],
                                restrict_to_custom_paths=True
                            )
                            if not dongle_ok or not dongle_payload:
                                st.error("Dongle terlepas sebelum sesi dimulai. Silakan login ulang.")
                                st.stop()
                            st.session_state.authenticated_user = selected_user
                            st.session_state.authenticated_dongle_root = str(Path(selected_dongle).resolve())
                            st.session_state.authenticated_dongle_uuid = dongle_payload.get("dongle_uuid")
                            st.session_state.auth_audit_details = report
                            st.success(f"🎉 {message}")
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error(f"❌ {message}")
                            st.json(report)

    # -------------------------------------------------------------------------
    # TAB 2: PENDAFTARAN PENGGUNA BARU
    # -------------------------------------------------------------------------
    with tab_register:
        st.subheader("Pendaftaran Akun Pengguna Baru")
        col_r1, col_r2 = st.columns(2)
        
        with col_r1:
            new_username = st.text_input("Username Baru (tanpa spasi)", key="reg_user")
            new_password = st.text_input("Kata Sandi Master", type="password", key="reg_pwd")
            confirm_pwd = st.text_input("Konfirmasi Kata Sandi", type="password", key="reg_pwd_confirm")
            
            target_dongle_options = get_available_dongle_paths()
            reg_dongle_path = st.selectbox(
                "Pilih Drive Tujuan Pembuatan File Kunci Dongle",
                options=target_dongle_options,
                format_func=lambda p: f"💾 Drive USB Flashdisk ({p})" if p != str(VIRTUAL_DONGLE_DIR) else f"📁 Virtual Dongle Folder ({p})",
                key="reg_dongle_select"
            )
            reg_dongle_mode = st.radio(
                "Mode penyimpanan dongle",
                ["USB terpisah (file di root)", "USB bersama (folder per user)"],
                key="reg_dongle_mode",
                help="USB bersama menyimpan kunci di <USB>/<username>/secure_dongle.key."
            )
            
        with col_r2:
            st.write("**Foto Rujukan Wajah (Biometrik):**")
            reg_bio_method = st.radio(
                "Pilihan Masukan Foto Wajah",
                ["Kamera Langsung", "Unggah Berkas Citra"],
                horizontal=True,
                key="reg_bio_radio"
            )
            
            reg_face_bytes = None
            if reg_bio_method == "Kamera Langsung":
                cam_reg = st.camera_input("Ambil foto rujukan wajah Anda", key="reg_cam")
                if cam_reg is not None:
                    reg_face_bytes = cam_reg.getvalue()
            else:
                up_reg = st.file_uploader("Unggah foto wajah beresolusi jelas", type=["jpg", "png", "jpeg"], key="reg_file_up")
                if up_reg is not None:
                    reg_face_bytes = up_reg.getvalue()
                    st.image(reg_face_bytes, width=150, caption="Foto Rujukan")
                    
        if st.button("📝 Daftarkan Pengguna Baru", type="primary", use_container_width=True):
            import re
            clean_input_user = new_username.strip().lower()
            if not clean_input_user or not new_password:
                st.error("Username dan kata sandi wajib diisi!")
            elif not re.match(r"^[a-zA-Z0-9_\-\.]{3,32}$", clean_input_user):
                st.error("Username tidak valid! Karakter khusus seperti '*', '?', ':', '/', '\\' tidak diizinkan oleh sistem berkas. Gunakan hanya huruf, angka, garis bawah (_), atau tanda hubung (-). Minimal 3 karakter.")
            elif new_password != confirm_pwd:
                st.error("Konfirmasi kata sandi tidak cocok!")
            elif reg_face_bytes is None:
                st.error("Wajib mengambil foto wajah sebagai rujukan biometrik!")
            else:
                with st.spinner("Mendaftarkan biometrik, membuat kunci dongle, dan melakukan hashing PBKDF2..."):
                    reg_ok, reg_msg, user_rec = register_user(
                        username=clean_input_user,
                        password=new_password,
                        face_image_input=reg_face_bytes,
                        dongle_target_path=Path(reg_dongle_path),
                        dongle_per_user_folder=(reg_dongle_mode == "USB bersama (folder per user)")
                    )
                    
                    if reg_ok:
                        st.success(f"✅ {reg_msg}")
                        st.info(f"File kunci digital dibuat pada: `{user_rec.get('dongle_key_path', reg_dongle_path)}`")
                        st.session_state.blockchain.record_login_audit(
                            actor=clean_input_user,
                            status="USER_REGISTERED",
                            factor_details={"dongle_path": reg_dongle_path}
                        )
                        time.sleep(1.5)
                        st.rerun()
                    else:
                        st.error(f"❌ {reg_msg}")

    # -------------------------------------------------------------------------
    # TAB 3: GENERATOR KUNCI DONGLE USB
    # -------------------------------------------------------------------------
    with tab_dongle_tool:
        st.subheader("🛠️ Pembuatan & Pemulihan Kunci Dongle USB")
        st.write("Gunakan fitur ini jika Anda baru saja memasang flashdisk baru dan ingin menulis file kunci digital (`secure_dongle.key`) yang sah ke dalam flashdisk tersebut.")
        
        tool_users = st.session_state.db.list_users()
        if not tool_users:
            st.warning("Belum ada akun terdaftar.")
        else:
            col_t1, col_t2 = st.columns(2)
            with col_t1:
                tool_selected_user = st.selectbox("Pilih Pemilik Kunci Dongle", options=tool_users, key="tool_user")
            with col_t2:
                tool_drives = get_available_dongle_paths()
                tool_selected_drive = st.selectbox("Pilih Flashdisk USB Tujuan", options=tool_drives, key="tool_drive")
            tool_dongle_mode = st.radio(
                "Mode penyimpanan",
                ["USB terpisah (file di root)", "USB bersama (folder per user)"],
                key="tool_dongle_mode",
                help="USB bersama membuat folder khusus sesuai username."
            )

            if st.button("💾 Tulis Berkas Kunci `secure_dongle.key` ke Flashdisk"):
                try:
                    key_path = generate_dongle_key(
                        Path(tool_selected_drive),
                        tool_selected_user,
                        per_user_folder=(tool_dongle_mode == "USB bersama (folder per user)")
                    )
                    st.success(f"✅ Dongle berhasil dibuat: `{key_path}`")
                except Exception as e:
                    st.error(f"Gagal membuat dongle: {e}")

    # TAB 4: KELOLA & HAPUS AKUN
    # -------------------------------------------------------------------------
    with tab_manage_users:
        st.subheader("🗑️ Pengelolaan & Penghapusan Akun Pengguna")
        st.write("Hapus akun yang tidak lagi digunakan atau akun uji coba:")
        
        m_users = st.session_state.db.list_users()
        if not m_users:
            st.info("Tidak ada pengguna terdaftar.")
        else:
            col_m1, col_m2 = st.columns([3, 1])
            with col_m1:
                del_user = st.selectbox("Pilih Akun yang Ingin Dihapus:", options=m_users, key="del_user_sel")
            with col_m2:
                st.write("")
                st.write("")
                if st.button(f"🗑️ Hapus Akun '{del_user}'", type="secondary", use_container_width=True):
                    delete_user_account(del_user)
                    st.success(f"Akun '{del_user}' dan seluruh berkas biometriknya berhasil dihapus.")
                    time.sleep(1)
                    st.rerun()


# =============================================================================
# TAMPILAN JIKA SUDAH LOGIN (WORKSPACE SECURE MESSENGER)
# =============================================================================
@st.fragment(run_every="1s")
def monitor_authenticated_dongle():
    """Pantau dongle sesi aktif setiap detik dan kunci sesi saat terlepas."""
    username = st.session_state.get("authenticated_user")
    root_value = st.session_state.get("authenticated_dongle_root")
    expected_uuid = st.session_state.get("authenticated_dongle_uuid")

    if not username or not root_value or not expected_uuid:
        st.session_state.dongle_disconnect_notice = (
            "🚨 Dongle terputus atau identitas dongle tidak ditemukan. "
            "Sesi telah dikunci otomatis. Silakan pasang dongle dan login kembali."
        )
        st.session_state.authenticated_user = None
        st.session_state.auth_audit_details = {}
        st.error("Sesi tidak memiliki identitas dongle yang valid. Silakan login ulang.")
        st.rerun()

    root = Path(root_value)
    # Drive fisik harus tetap terpasang. Folder virtual tidak dianggap sebagai
    # pengganti jika login dilakukan memakai flashdisk fisik.
    if not root.exists():
        st.session_state.dongle_disconnect_notice = (
            "🚨 DONGLE TERPUTUS! Flashdisk/dongle USB tidak terdeteksi. "
            "Sesi telah dikunci otomatis demi keamanan. Pasang kembali dongle untuk login ulang."
        )
        st.session_state.authenticated_user = None
        st.session_state.auth_audit_details = {}
        st.session_state.authenticated_dongle_root = None
        st.session_state.authenticated_dongle_uuid = None
        st.error("🚨 Dongle/flashdisk terlepas. Sesi dikunci; silakan pasang kembali dan login ulang.")
        st.rerun()

    valid, _, payload = verify_dongle(
        username=username,
        custom_search_paths=[root],
        restrict_to_custom_paths=True
    )
    key_path = Path(payload.get("dongle_key_path", "")).resolve() if payload else None
    try:
        same_drive = key_path is not None and os.path.commonpath(
            [str(root.resolve()), str(key_path)]
        ) == str(root.resolve())
    except (ValueError, OSError):
        same_drive = False

    if not valid or not same_drive or payload.get("dongle_uuid") != expected_uuid:
        st.session_state.dongle_disconnect_notice = (
            "🚨 DONGLE TERPUTUS / TIDAK VALID! Dongle berubah atau tidak dapat diverifikasi. "
            "Sesi telah dikunci otomatis. Pastikan menggunakan dongle yang benar, lalu login kembali."
        )
        st.session_state.authenticated_user = None
        st.session_state.auth_audit_details = {}
        st.session_state.authenticated_dongle_root = None
        st.session_state.authenticated_dongle_uuid = None
        st.error("🚨 Dongle tidak valid atau berubah. Sesi dikunci; silakan login ulang.")
        st.rerun()

    st.caption("🟢 Dongle terdeteksi — pemeriksaan otomatis aktif (setiap 1 detik).")


def render_authenticated_workspace():
    current_user = st.session_state.authenticated_user
    
    # -------------------------------------------------------------------------
    # SIDEBAR: PROFIL & NAVIGASI MENU
    # -------------------------------------------------------------------------
    with st.sidebar:
        st.markdown(f"### 👤 Akun: **{current_user.upper()}**")
        st.markdown('<div class="security-badge">🔒 3FA Authenticated</div>', unsafe_allow_html=True)
        
        # Info rincian 3FA
        with st.expander("ℹ️ Status Verifikasi Keamanan"):
            st.write("✅ **Dongle USB:** Terverifikasi")
            st.write("✅ **Biometrik:** Wajah Cocok")
            st.write("✅ **Password:** PBKDF2 Valid")
            
        st.write("---")
        
        menu = st.radio(
            "Navigasi Modul:",
            [
                "💬 Chat Super Enkripsi (Teks)",
                "📁 Kirim Berkas Rahasia (ChaCha20)",
                "🎨 Steganografi Multimedia (LSB)",
                "⛓️ Blockchain Ledger & Auditor",
                "🗄️ Inspektur Basis Data (SQLite)",
                "🚪 Keluar (Logout)"
            ]
        )
        
        st.write("---")
        st.caption("Tugas Akhir Kriptografi © 2026")

    # -------------------------------------------------------------------------
    # MENU 1: CHAT SUPER ENKRIPSI (TEKS)
    # -------------------------------------------------------------------------
    if menu == "💬 Chat Super Enkripsi (Teks)":
        st.markdown("## 💬 Pesan Teks Rahasia (Super Enkripsi)")
        st.markdown("**Alur:** Plaintext $\\rightarrow$ **Vigenère Cipher (Klasik)** $\\rightarrow$ **AES-256-GCM (Modern AEAD)** $\\rightarrow$ Ciphertext")

        users_list = [u for u in st.session_state.db.list_users() if u != current_user]
        if not users_list:
            st.warning("Belum ada kontak lain. Silakan daftarkan akun kedua terlebih dahulu di tab pendaftaran untuk simulasi berkirim pesan!")
        else:
            # Hitung badge unread per kontak
            unread_counts = st.session_state.db.get_unread_message_counts(current_user)

            # Format label kontak dengan badge
            def _contact_label(u):
                cnt = unread_counts.get(u, 0)
                if cnt > 0:
                    return f"{u.upper()}  🔒 {cnt} Pesan terenkripsi"
                return u.upper()

            recipient = st.selectbox(
                "Percakapan dengan:",
                options=users_list,
                format_func=_contact_label
            )

            tab_send, tab_inbox = st.tabs(["✉️ Kirim Pesan", "📥 Percakapan & Buka Pesan"])

            # -----------------------------------------------------------------
            # SUB-TAB: KIRIM PESAN
            # -----------------------------------------------------------------
            with tab_send:
                st.markdown("### ✉️ Kirim Pesan Terenkripsi")
                st.info(
                    "⚠️ **Penting:** Password dan Key yang Anda isi di bawah harus disampaikan kepada penerima "
                    "melalui **jalur aman lain** (misalnya tatap muka atau saluran terenkripsi berbeda). "
                    "Jangan kirimkan password/key melalui aplikasi ini!"
                )

                new_message_text = st.text_area(
                    "Tulis pesan rahasia:",
                    placeholder="Ketik pesan Anda di sini...",
                    key="chat_msg_input"
                )

                col_k1, col_k2 = st.columns(2)
                with col_k1:
                    send_password = st.text_input(
                        "🔑 Password (passphrase AES-256)",
                        type="password",
                        key="send_password",
                        help="Passphrase untuk lapisan enkripsi AES-256-GCM. Sampaikan ke penerima!"
                    )
                with col_k2:
                    send_key = st.text_input(
                        "🗝️ Key (kunci Vigenère)",
                        type="password",
                        key="send_key",
                        help="Kunci untuk lapisan Vigenère Cipher. Sampaikan ke penerima!"
                    )

                send_clicked = st.button("Kirim Pesan Terenkripsi 🚀", type="primary", use_container_width=True)

                if send_clicked:
                    if not new_message_text.strip():
                        st.error("Pesan tidak boleh kosong!")
                    elif not send_password:
                        st.error("Password wajib diisi!")
                    elif not send_key:
                        st.error("Key (kunci Vigenère) wajib diisi!")
                    else:
                        # 1. Super Enkripsi: Vigenère (key) → AES-256-GCM (password)
                        enc_res = super_encrypt(new_message_text, send_key, send_password, mode="extended")
                        final_cipher = enc_res["final_ciphertext"]

                        # Simpan info enkripsi ke session state agar tetap tampil setelah rerun
                        st.session_state.last_encryption_info = {
                            "plaintext": new_message_text,
                            "intermediate": enc_res["intermediate_vigenere"],
                            "final_cipher": final_cipher,
                            "time_ms": enc_res["encryption_time_ms"],
                            "recipient": recipient
                        }

                        # 2. Simpan ke Database: content (plaintext untuk arsip DB), super_ciphertext
                        msg_id, msg_hash = st.session_state.db.store_message(
                            sender=current_user,
                            recipient=recipient,
                            message_type="TEXT",
                            content=new_message_text,
                            super_ciphertext=final_cipher
                        )

                        # 3. Catat ke Blockchain: event MSG_RECEIVED (hanya hash, bukan password/key)
                        st.session_state.blockchain.record_message_transaction(
                            sender=current_user,
                            recipient=recipient,
                            message_hash=msg_hash,
                            asset_type="TEXT_SUPER_ENCRYPTED"
                        )
                        st.session_state.blockchain.record_message_event(
                            event_type="MSG_RECEIVED",
                            actor=recipient,
                            message_hash=msg_hash
                        )

                        st.success("✅ Pesan berhasil dienkripsi bertingkat, disimpan ke basis data, dan dicatat di Blockchain!")
                        time.sleep(0.5)
                        st.rerun()

                # Tampilkan rincian super enkripsi pesan terakhir
                if "last_encryption_info" in st.session_state and st.session_state.last_encryption_info:
                    last_enc = st.session_state.last_encryption_info
                    with st.expander(f"🔍 Bukti Kriptografi Pesan Terakhir ke '{last_enc['recipient'].upper()}'", expanded=True):
                        st.write(f"**1. Teks Asli (Plaintext):** `{last_enc['plaintext']}`")
                        st.write(f"**2. Hasil Cipher Klasik (Vigenère Intermediate):** `{last_enc['intermediate']}`")
                        st.write(f"**3. Ciphertext Final Siap Kirim (AES-256-GCM + Nonce + Tag):**")
                        st.code(last_enc['final_cipher'], language="text")
                        st.caption(f"⚡ Waktu Komputasi Enkripsi: {last_enc['time_ms']} ms")

            # -----------------------------------------------------------------
            # SUB-TAB: PERCAKAPAN & BUKA PESAN
            # -----------------------------------------------------------------
            with tab_inbox:
                st.subheader(f"📥 Riwayat Percakapan dengan '{recipient.upper()}'")

                # Tombol refresh manual
                if st.button("🔄 Refresh Percakapan", key="refresh_convo"):
                    st.rerun()

                convo = st.session_state.db.get_conversation(current_user, recipient)

                if not convo:
                    st.info("Belum ada riwayat pesan dengan kontak ini.")
                else:
                    for msg in convo:
                        is_me = (msg["sender"].lower() == current_user.lower())
                        bubble_class = "chat-bubble-sent" if is_me else "chat-bubble-recv"
                        sender_label = "Anda (Saya)" if is_me else recipient.upper()
                        msg_id = msg["id"]
                        has_super = bool(msg.get("super_ciphertext"))
                        is_opened = bool(msg.get("is_opened", 0))

                        # Tentukan konten yang ditampilkan
                        if is_me:
                            # Pesan keluar: tampilkan plaintext arsip DB
                            display_content = msg.get("content_plaintext", "[konten tidak tersedia]")
                            if not msg.get("integrity_verified", True):
                                display_content = msg.get("content_plaintext", "[DATA RUSAK]")
                            status_line = ""
                        else:
                            # Pesan masuk dari orang lain
                            if not has_super:
                                # Pesan lama (sebelum fitur ini), tampilkan langsung
                                display_content = msg.get("content_plaintext", "[konten tidak tersedia]")
                                status_line = "<span style='font-size:0.72rem;color:#9CA3AF;'>⚠️ Format lama (tanpa super-enkripsi)</span>"
                            elif is_opened:
                                # Sudah dibuka: tampilkan plaintext arsip
                                display_content = msg.get("content_plaintext", "[konten tidak tersedia]")
                                status_line = "<span style='font-size:0.72rem;color:#10B981;'>✅ Sudah dibuka</span>"
                            else:
                                # Belum dibuka: sembunyikan isi
                                display_content = "🔒 Pesan terenkripsi"
                                status_line = "<span style='font-size:0.72rem;color:#F59E0B;'>🔒 Belum dibuka</span>"

                        st.markdown(f"""
                        <div class="{bubble_class}">
                            <div style="font-size: 0.8rem; font-weight: bold; color: #374151;">{sender_label} • <span style="font-weight: normal; color: #6B7280;">{msg['timestamp'][:19]}</span></div>
                            <div style="font-size: 1.05rem; margin-top: 4px; color: #111827;">{display_content}</div>
                            <div style="font-size: 0.72rem; color: #9CA3AF; margin-top: 4px;">SHA-256 Proof: <code>{msg['message_hash'][:24]}...</code> {status_line}</div>
                        </div>
                        """, unsafe_allow_html=True)

                        # Tombol "Buka Pesan" hanya untuk pesan masuk yang belum dibuka dan punya super_ciphertext
                        if not is_me and has_super and not is_opened:
                            btn_key = f"open_btn_{msg_id}"
                            if st.button(f"🔓 Buka Pesan (ID #{msg_id})", key=btn_key, use_container_width=False):
                                st.session_state[f"show_open_dialog_{msg_id}"] = True

                            # Dialog buka pesan (inline expander)
                            if st.session_state.get(f"show_open_dialog_{msg_id}", False):
                                with st.expander(f"🔐 Masukkan Kredensial untuk Membuka Pesan #{msg_id}", expanded=True):
                                    # Cek status lockout
                                    lock_status = st.session_state.db.get_lock_status(msg_id)

                                    if lock_status["locked"]:
                                        mins_left = int(lock_status["remaining_seconds"] // 60) + 1
                                        st.error(
                                            f"🔒 Pesan ini terkunci karena terlalu banyak percobaan gagal. "
                                            f"Coba lagi dalam **~{mins_left} menit**."
                                        )
                                    else:
                                        attempts_left = 5 - lock_status["attempts"]
                                        if lock_status["attempts"] > 0:
                                            st.warning(f"⚠️ Sisa percobaan: **{attempts_left}** kali sebelum dikunci 5 menit.")

                                        col_d1, col_d2 = st.columns(2)
                                        with col_d1:
                                            dialog_password = st.text_input(
                                                "Password (passphrase AES-256)",
                                                type="password",
                                                key=f"dlg_pwd_{msg_id}"
                                            )
                                        with col_d2:
                                            dialog_key = st.text_input(
                                                "Key (kunci Vigenère)",
                                                key=f"dlg_key_{msg_id}"
                                            )

                                        col_btn1, col_btn2 = st.columns([2, 1])
                                        with col_btn1:
                                            decrypt_clicked = st.button(
                                                "🔓 Dekripsi Pesan",
                                                key=f"dlg_decrypt_{msg_id}",
                                                type="primary",
                                                use_container_width=True
                                            )
                                        with col_btn2:
                                            if st.button("✖ Batal", key=f"dlg_cancel_{msg_id}", use_container_width=True):
                                                st.session_state[f"show_open_dialog_{msg_id}"] = False
                                                st.rerun()

                                        if decrypt_clicked:
                                            if not dialog_password or not dialog_key:
                                                st.error("Password dan Key wajib diisi!")
                                            else:
                                                try:
                                                    # Dekripsi: AES-256-GCM (password) → Vigenère (key)
                                                    dec_result = super_decrypt(
                                                        msg["super_ciphertext"],
                                                        vigenere_key=dialog_key,
                                                        aes_key=dialog_password,
                                                        mode="extended"
                                                    )
                                                    recovered_text = dec_result["plaintext"]

                                                    # Verifikasi: plaintext harus cocok dengan arsip DB
                                                    # (defense: pastikan tidak ada tampilan setengah benar)
                                                    db_plaintext = msg.get("content_plaintext", "")
                                                    if recovered_text != db_plaintext:
                                                        raise ValueError(
                                                            "Verifikasi gagal: plaintext hasil dekripsi tidak cocok dengan arsip."
                                                        )

                                                    # SUKSES: Tandai dibuka, tampilkan plaintext
                                                    st.session_state.db.mark_message_opened(msg_id)
                                                    st.session_state[f"show_open_dialog_{msg_id}"] = False

                                                    # Catat ke Blockchain: event MSG_OPENED
                                                    st.session_state.blockchain.record_message_event(
                                                        event_type="MSG_OPENED",
                                                        actor=current_user,
                                                        message_hash=msg["message_hash"]
                                                    )

                                                    st.success(f"✅ Pesan berhasil didekripsi:\n\n**{recovered_text}**")
                                                    time.sleep(1.5)
                                                    st.rerun()

                                                except ValueError:
                                                    # GAGAL: Jangan beri tahu mana yang salah
                                                    lock_result = st.session_state.db.increment_open_attempts(msg_id)

                                                    # Catat ke Blockchain: event MSG_OPEN_FAILED
                                                    st.session_state.blockchain.record_message_event(
                                                        event_type="MSG_OPEN_FAILED",
                                                        actor=current_user,
                                                        message_hash=msg["message_hash"]
                                                    )

                                                    if lock_result["locked"]:
                                                        st.error(
                                                            "❌ Password atau key salah. "
                                                            "Pesan telah **dikunci selama 5 menit** karena terlalu banyak percobaan."
                                                        )
                                                        time.sleep(1)
                                                        st.rerun()
                                                    else:
                                                        remaining_tries = 5 - lock_result["attempts"]
                                                        st.error(
                                                            f"❌ Password atau key salah. "
                                                            f"Sisa percobaan: **{remaining_tries}** kali."
                                                        )

    # -------------------------------------------------------------------------
    # MENU 2: ENKRIPSI BERKAS (CHACHA20-POLY1305)
    # -------------------------------------------------------------------------
    elif menu == "📁 Kirim Berkas Rahasia (ChaCha20)":
        st.markdown("## 📁 Pengiriman Berkas Rahasia (File Encryption)")
        st.markdown("**Algoritma Berbeda:** Berkas dokumen/biner diamankan menggunakan **ChaCha20-Poly1305** (AEAD Stream Cipher RFC 8439) dengan kunci derivasi independen.")
        
        tab_enc_file, tab_dec_file = st.tabs(["🔒 Enkripsi & Kirim Berkas", "🔓 Dekripsi Berkas Terenkripsi"])
        
        with tab_enc_file:
            uploaded_file = st.file_uploader("Pilih berkas apa saja (PDF, DOCX, ZIP, JPG, dll):", type=None)
            file_key = st.text_input("Kunci Enkripsi Berkas (Passphrase)", value="KunciRahasiaBerkas2026", type="password", key="fk_enc")
            
            if uploaded_file is not None:
                st.write(f"📄 Nama berkas: `{uploaded_file.name}` ({uploaded_file.size} bytes)")
                if st.button("🔒 Enkripsi Berkas dengan ChaCha20-Poly1305", type="primary"):
                    raw_bytes = uploaded_file.getvalue()
                    encrypted_container = encrypt_file_bytes(raw_bytes, uploaded_file.name, file_key)
                    
                    # Hitung hash berkas terenkripsi
                    import hashlib
                    file_sha = hashlib.sha256(encrypted_container).hexdigest()
                    
                    # Catat ke Blockchain Ledger
                    st.session_state.blockchain.record_file_transaction(
                        sender=current_user,
                        recipient="ALL_AUTHORIZED",
                        file_hash=file_sha,
                        filename=uploaded_file.name
                    )
                    
                    st.success("✅ Berkas berhasil dienkripsi dan bukti SHA-256 dicatat ke Blockchain!")
                    st.download_button(
                        label="⬇️ Unduh Berkas Terenkripsi (.enc)",
                        data=encrypted_container,
                        file_name=f"{uploaded_file.name}.enc",
                        mime="application/octet-stream"
                    )
                    
        with tab_dec_file:
            enc_file_upload = st.file_uploader("Unggah berkas terenkripsi (.enc):", type=None, key="up_enc_file")
            file_dec_key = st.text_input("Kunci Dekripsi Berkas", type="password", key="fk_dec")
            
            if enc_file_upload is not None:
                if st.button("🔓 Dekripsi & Pulihkan Berkas Asli", type="primary"):
                    try:
                        recovered_bytes, orig_name, meta = decrypt_file_bytes(enc_file_upload.getvalue(), file_dec_key)
                        st.success(f"🎉 Berkas berhasil didekripsi dengan integritas valid! Nama asli: `{orig_name}`")
                        st.json(meta)
                        st.download_button(
                            label=f"⬇️ Unduh Berkas Asli ({orig_name})",
                            data=recovered_bytes,
                            file_name=orig_name
                        )
                    except ValueError as e:
                        st.error(f"❌ {str(e)}")

    # -------------------------------------------------------------------------
    # MENU 3: STEGANOGRAFI MULTIMEDIA (GAMBAR, AUDIO MP3, VIDEO MP4)
    # -------------------------------------------------------------------------
    elif menu == "🎨 Steganografi Multimedia (LSB)":
        st.markdown("## 🎨 Steganografi Multimedia (PNG, MP3, MP4)")
        st.markdown("**Alur:** Pesan Rahasia $\\xrightarrow{\\text{AES-256-GCM}}$ Ciphertext $\\xrightarrow{\\text{Stego Insertion}}$ Media Pembawa.")
        
        stego_type = st.radio("Pilih Tipe Media Pembawa:", ["🖼️ Gambar (PNG)", "🎵 Audio (MP3)", "🎬 Video (MP4)"], horizontal=True)
        
        tab_hide, tab_reveal = st.tabs(["🔒 Sembunyikan Pesan (Embed)", "🔓 Ekstraksi Pesan (Extract)"])
        
        # ---------------------------------------------------------------------
        # TAB HIDE (EMBED)
        # ---------------------------------------------------------------------
        with tab_hide:
            stego_msg = st.text_area("Pesan Rahasia yang Ingin Disembunyikan:", "Operasi Alpha-99 telah disetujui. Bergerak sesuai rencana.")
            stego_key = st.text_input("Kunci Pra-Enkripsi AES-256:", value="KunciStegoAES2026", type="password", key="stego_hide_key")
            
            if stego_type == "🖼️ Gambar (PNG)":
                carrier_img_file = st.file_uploader("Pilih Citra Pembawa (PNG / JPG / BMP):", type=["png", "jpg", "jpeg", "bmp"])
                if carrier_img_file is not None and st.button("🖼️ Sisipkan ke Citra PNG", type="primary"):
                    tmp_src = DATA_DIR / f"temp_carrier_{int(time.time())}.png"
                    tmp_out = DATA_DIR / f"stego_result_{int(time.time())}.png"
                    tmp_src.write_bytes(carrier_img_file.getvalue())
                    
                    try:
                        info = embed_image(tmp_src, stego_msg, stego_key, tmp_out)
                        st.success(f"✅ Pesan berhasil dienkripsi AES-256 dan disisipkan ke LSB PNG!")
                        st.json(info)
                        st.image(str(tmp_out), caption="Citra Stego PNG Hasil (Visual Tidak Berubah)", width=350)
                        st.download_button("⬇️ Unduh Citra Stego (.png)", data=tmp_out.read_bytes(), file_name="stego_image.png", mime="image/png")
                    except ValueError as e:
                        st.error(f"❌ {str(e)}")
                        
            elif stego_type == "🎵 Audio (MP3)":
                carrier_audio_file = st.file_uploader("Pilih Berkas Audio Pembawa (MP3 / WAV):", type=["mp3", "wav"])
                col_gen1, _ = st.columns([2, 3])
                with col_gen1:
                    if st.button("🎵 Buat Audio MP3 Uji Otomatis"):
                        dummy_path = DATA_DIR / "sample_audio.mp3"
                        create_dummy_mp3(dummy_path, duration_sec=3.0)
                        st.success(f"Audio uji MP3 berhasil dibuat: `{dummy_path.name}`")
                        
                if carrier_audio_file is not None and st.button("🎵 Sisipkan ke Audio", type="primary"):
                    ext = "wav" if carrier_audio_file.name.lower().endswith(".wav") else "mp3"
                    tmp_audio_src = DATA_DIR / f"temp_audio_{int(time.time())}.{ext}"
                    tmp_audio_out = DATA_DIR / f"stego_audio_{int(time.time())}.{ext}"
                    tmp_audio_src.write_bytes(carrier_audio_file.getvalue())
                    
                    try:
                        info = embed_audio(tmp_audio_src, stego_msg, stego_key, tmp_audio_out)
                        st.success(f"✅ Pesan berhasil disisipkan ke audio ({info.get('format', ext.upper())})!")
                        st.json(info)
                        mime_type = "audio/mpeg" if ext == "mp3" else "audio/wav"
                        st.audio(str(tmp_audio_out), format=mime_type)
                        st.download_button(
                            f"⬇️ Unduh Audio Stego (.{ext})",
                            data=tmp_audio_out.read_bytes(),
                            file_name=f"stego_audio.{ext}",
                            mime=mime_type
                        )
                    except ValueError as e:
                        st.error(f"❌ {str(e)}")

            elif stego_type == "🎬 Video (MP4)":
                st.write("Pesan terenkripsi AES-256-GCM disisipkan ke dalam kontainer video MP4 (ISO BMFF Free-Space Box) sehingga video tetap 100% kompatibel dan dapat langsung diputar.")
                col_vgen, _ = st.columns([2, 3])
                with col_vgen:
                    if st.button("🎬 Buat Video MP4 Uji Otomatis"):
                        dummy_vid = DATA_DIR / "sample_video.mp4"
                        create_dummy_mp4(dummy_vid, num_frames=20)
                        st.success(f"Video uji MP4 berhasil dibuat: `{dummy_vid.name}`")
                        
                carrier_vid_file = st.file_uploader("Pilih Berkas Video Pembawa (MP4 / AVI):", type=["mp4", "avi"])
                if carrier_vid_file is not None and st.button("🎬 Sisipkan ke Video", type="primary"):
                    ext = "avi" if carrier_vid_file.name.lower().endswith(".avi") else "mp4"
                    tmp_vid_src = DATA_DIR / f"temp_vid_{int(time.time())}.{ext}"
                    tmp_vid_out = DATA_DIR / f"stego_video_{int(time.time())}.{ext}"
                    tmp_vid_src.write_bytes(carrier_vid_file.getvalue())
                    
                    with st.spinner("Menyisipkan pesan rahasia ke berkas video..."):
                        try:
                            info = embed_video(tmp_vid_src, stego_msg, stego_key, tmp_vid_out)
                            st.success(f"✅ Pesan berhasil disisipkan ke video ({info.get('format', ext.upper())})!")
                            st.json(info)
                            if ext == "mp4":
                                st.video(str(tmp_vid_out))
                            mime_type = "video/mp4" if ext == "mp4" else "video/x-msvideo"
                            st.download_button(
                                f"⬇️ Unduh Video Stego (.{ext})",
                                data=tmp_vid_out.read_bytes(),
                                file_name=f"stego_video.{ext}",
                                mime=mime_type
                            )
                        except ValueError as e:
                            st.error(f"❌ {str(e)}")

        # ---------------------------------------------------------------------
        # TAB REVEAL (EXTRACT)
        # ---------------------------------------------------------------------
        with tab_reveal:
            st.write("Unggah media steganografi untuk mengekstrak dan mendekripsi pesan rahasia:")
            ext_key = st.text_input("Kunci Dekripsi AES-256:", type="password", key="stego_ext_key")
            
            if stego_type == "🖼️ Gambar (PNG)":
                stego_img_in = st.file_uploader("Unggah Citra Stego PNG:", type=["png"], key="ext_png")
                if stego_img_in is not None and st.button("🔓 Ekstraksi Pesan dari Gambar", type="primary"):
                    tmp_path = DATA_DIR / f"ext_img_{int(time.time())}.png"
                    tmp_path.write_bytes(stego_img_in.getvalue())
                    try:
                        secret_recovered = extract_image(tmp_path, ext_key)
                        st.success("🎉 Pesan Rahasia Berhasil Diekstraksi & Didekripsi:")
                        st.info(secret_recovered)
                    except ValueError as e:
                        st.error(f"❌ {str(e)}")
                        
            elif stego_type == "🎵 Audio (MP3)":
                stego_audio_in = st.file_uploader("Unggah Audio Stego (MP3 / WAV):", type=["mp3", "wav"], key="ext_audio")
                if stego_audio_in is not None and st.button("🔓 Ekstraksi Pesan dari Audio", type="primary"):
                    ext = "wav" if stego_audio_in.name.lower().endswith(".wav") else "mp3"
                    tmp_path = DATA_DIR / f"ext_audio_{int(time.time())}.{ext}"
                    tmp_path.write_bytes(stego_audio_in.getvalue())
                    try:
                        secret_recovered = extract_audio(tmp_path, ext_key)
                        st.success("🎉 Pesan Rahasia Berhasil Diekstraksi & Didekripsi:")
                        st.info(secret_recovered)
                    except ValueError as e:
                        st.error(f"❌ {str(e)}")

            elif stego_type == "🎬 Video (MP4)":
                stego_vid_in = st.file_uploader("Unggah Video Stego (MP4 / AVI):", type=["mp4", "avi"], key="ext_video")
                if stego_vid_in is not None and st.button("🔓 Ekstraksi Pesan dari Video", type="primary"):
                    ext = "avi" if stego_vid_in.name.lower().endswith(".avi") else "mp4"
                    tmp_path = DATA_DIR / f"ext_vid_{int(time.time())}.{ext}"
                    tmp_path.write_bytes(stego_vid_in.getvalue())
                    with st.spinner("Mengekstrak dan mendekripsi pesan dari video..."):
                        try:
                            secret_recovered = extract_video(tmp_path, ext_key)
                            st.success("🎉 Pesan Rahasia Berhasil Diekstraksi & Didekripsi:")
                            st.info(secret_recovered)
                        except ValueError as e:
                            st.error(f"❌ {str(e)}")

    # -------------------------------------------------------------------------
    # MENU 4: BLOCKCHAIN LEDGER & AUDIT TRAIL
    # -------------------------------------------------------------------------
    elif menu == "⛓️ Blockchain Ledger & Auditor":
        st.markdown("## ⛓️ Blockchain Audit Trail (Buku Besar SHA-256)")
        st.markdown("Buku besar digital buatan sendiri dengan konsensus **Proof-of-Work (PoW)** untuk menjamin bahwa seluruh pengiriman pesan, transfer berkas, dan log audit login tidak dapat diubah (*tamper-evident*).")
        
        col_bc1, col_bc2 = st.columns([3, 1])
        with col_bc1:
            st.write(f"Total Blok Tertambang: **{len(st.session_state.blockchain.chain)} Blok**")
        with col_bc2:
            audit_clicked = st.button("🔍 Audit Keutuhan Rantai (validate_chain)", type="primary", use_container_width=True)
            
        if audit_clicked:
            is_valid, msg, broken_idx = st.session_state.blockchain.validate_chain()
            if is_valid:
                st.success(f"🛡️ **STATUS AMAN:** {msg}")
            else:
                st.error(f"🚨 **PERINGATAN MANIPULASI:** {msg}")
                
        st.write("---")
        
        # Render Kartu Blok
        for b in reversed(st.session_state.blockchain.chain):
            with st.container():
                st.markdown(f"""
                <div class="block-card">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="font-weight: 800; font-size: 1.15rem; color: #1E3A8A;">📦 Blok #{b.index}</span>
                        <span style="font-size: 0.85rem; color: #64748B;">🕒 {b.timestamp[:19]} UTC</span>
                    </div>
                    <div style="margin-top: 8px; font-size: 0.88rem;">
                        <div><b>Hash Blok:</b> <code>{b.hash}</code></div>
                        <div><b>Prev Hash:</b> <code>{b.prev_hash}</code></div>
                        <div><b>Proof-of-Work Nonce:</b> <code>{b.nonce}</code> (Difficulty: {st.session_state.blockchain.difficulty})</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                with st.expander(f"Lihat Muatan Transaksi Blok #{b.index}"):
                    st.json(b.data)

    # -------------------------------------------------------------------------
    # MENU 5: INSPEKTUR BASIS DATA (SQLITE)
    # -------------------------------------------------------------------------
    elif menu == "🗄️ Inspektur Basis Data (SQLite)":
        st.markdown("## 🗄️ Inspektur Penyimpanan Basis Data (Data-at-Rest)")
        st.markdown("Membuktikan secara langsung bahwa seluruh rekaman pesan penting disimpan dalam keadaan **terenkripsi penuh di disk fisik (AES-256-GCM)**.")
        
        # Audit Integritas SQLite
        is_clean, total_rows, corrupted = st.session_state.db.verify_all_records_integrity()
        if is_clean:
            st.success(f"✅ Integritas SQLite Sempurna: Seluruh {total_rows} pesan memiliki Authentication Tag AES-GCM yang valid.")
        else:
            st.error(f"🚨 Manipulasi Terdeteksi di Basis Data! Baris yang rusak: {corrupted}")
            
        st.write("---")
        st.subheader("Data Mentah dari Berkas `app_database.db` (Tanpa Lapisan Dekripsi)")
        st.write("Perhatikan bahwa kolom `encrypted_content`, `content_nonce`, dan `content_tag` berada dalam bentuk heksadesimal murni. Teks asli tidak pernah bocor ke disk:")
        
        # Query langsung ke database
        import sqlite3
        raw_conn = sqlite3.connect(str(st.session_state.db.db_path))
        raw_conn.row_factory = sqlite3.Row
        cur = raw_conn.cursor()
        cur.execute("SELECT id, sender, recipient, timestamp, message_type, encrypted_content, content_nonce, content_tag, message_hash FROM messages ORDER BY id DESC LIMIT 10;")
        rows = [dict(r) for r in cur.fetchall()]
        raw_conn.close()
        
        if rows:
            st.dataframe(rows, use_container_width=True)
        else:
            st.info("Belum ada pesan yang tersimpan di basis data.")

    # -------------------------------------------------------------------------
    # MENU 6: LOGOUT
    # -------------------------------------------------------------------------
    elif menu == "🚪 Keluar (Logout)":
        st.session_state.authenticated_user = None
        st.session_state.auth_audit_details = {}
        st.session_state.authenticated_dongle_root = None
        st.session_state.authenticated_dongle_uuid = None
        st.info("Sesi aman telah ditutup. Mengalihkan ke halaman login...")
        time.sleep(1)
        st.rerun()


# =============================================================================
# ENTRY POINT APLIKASI
# =============================================================================
def main():
    if st.session_state.authenticated_user is None:
        render_auth_view()
    else:
        monitor_authenticated_dongle()
        # Fragment dapat menghentikan sesi dan memicu rerun jika dongle hilang.
        if st.session_state.authenticated_user is not None:
            render_authenticated_workspace()


if __name__ == "__main__":
    main()

