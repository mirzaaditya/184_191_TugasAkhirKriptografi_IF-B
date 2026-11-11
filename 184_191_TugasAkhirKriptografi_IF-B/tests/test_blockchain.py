"""
==============================================================================
SKRIP PENGUJIAN OTOMATIS: MODUL BLOCKCHAIN AUDIT TRAIL (TAHAP 6)
==============================================================================
Menjalankan serangkaian pengujian blockchain komprehensif:
1. Uji Pembuatan Genesis Block (Inisialisasi Rantai & Bukti PoW Pertama)
2. Uji Penambangan & Pencatatan Transaksi Pesan (Message Hash Recording)
3. Uji Penambangan & Pencatatan Pengiriman Berkas (File SHA-256 Hash)
4. Uji Penambangan & Pencatatan Log Audit Login Pengguna
5. Uji Validasi Rantai (validate_chain) pada kondisi normal
6. Uji Persistensi Ledger: Memuat ulang rantai dari berkas JSON di disk
7. Uji Deteksi Manipulasi Data (Tamper Attack Detection):
   Membuktikan bahwa perubahan 1 kata di dalam blok langsung membatalkan seluruh rantai!
==============================================================================
"""

import sys
from pathlib import Path

# Tambahkan root proyek ke sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from modules.blockchain.chain import Blockchain
from config.settings import DATA_DIR


def run_tests():
    print("=" * 75)
    print("        PENGUJIAN MODUL BLOCKCHAIN SHA-256 & AUDIT TRAIL (TAHAP 6)")
    print("=" * 75)
    
    test_ledger_file = DATA_DIR / "test_blockchain_ledger.json"
    if test_ledger_file.exists():
        test_ledger_file.unlink()
        
    diff = 2  # Target difficulty: awalan "00"
    bc = Blockchain(ledger_path=test_ledger_file, difficulty=diff)
    
    # -------------------------------------------------------------------------
    # UJI 1: GENESIS BLOCK
    # -------------------------------------------------------------------------
    print("\n[UJI 1] Pembuatan Genesis Block (Blok #0)")
    assert len(bc.chain) == 1, "GAGAL: Rantai harus memiliki 1 Genesis Block!"
    genesis = bc.chain[0]
    print(f"  * Genesis Index     : #{genesis.index}")
    print(f"  * Prev Hash         : {genesis.prev_hash[:16]}... (64 zeros)")
    print(f"  * Genesis Hash      : {genesis.hash}")
    print(f"  * PoW Nonce         : {genesis.nonce}")
    assert genesis.index == 0
    assert genesis.prev_hash == "0" * 64
    assert genesis.hash.startswith("0" * diff), "GAGAL: Genesis block tidak memenuhi syarat PoW!"
    print("  [PASSED] Genesis Block berhasil dibuat dan ditambang dengan Proof-of-Work.")

    # -------------------------------------------------------------------------
    # UJI 2: PENCATATAN TRANSAKSI PESAN (MESSAGE RECORDING)
    # -------------------------------------------------------------------------
    print("\n[UJI 2] Penambangan Blok Transaksi Pesan (Message Hash)")
    dummy_msg_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    b_msg = bc.record_message_transaction(
        sender="alice",
        recipient="bob",
        message_hash=dummy_msg_hash,
        asset_type="TEXT"
    )
    print(f"  * Blok #{b_msg.index} Ditambang : Hash={b_msg.hash}")
    print(f"  * Prev Hash Cocok     : {b_msg.prev_hash == genesis.hash}")
    print(f"  * Nonce PoW           : {b_msg.nonce}")
    assert b_msg.index == 1
    assert b_msg.prev_hash == genesis.hash
    assert b_msg.hash.startswith("0" * diff)
    print("  [PASSED] Transaksi pesan berhasil diikat ke dalam blok #1.")

    # -------------------------------------------------------------------------
    # UJI 3: PENCATATAN TRANSAKSI PENGIRIMAN BERKAS (FILE RECORDING)
    # -------------------------------------------------------------------------
    print("\n[UJI 3] Penambangan Blok Pengiriman Berkas (File SHA-256)")
    dummy_file_sha = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
    b_file = bc.record_file_transaction(
        sender="bob",
        recipient="alice",
        file_hash=dummy_file_sha,
        filename="rencana_strategis.pdf.enc"
    )
    print(f"  * Blok #{b_file.index} Ditambang : Hash={b_file.hash}")
    print(f"  * Prev Hash Cocok     : {b_file.prev_hash == b_msg.hash}")
    assert b_file.index == 2
    assert b_file.prev_hash == b_msg.hash
    assert b_file.hash.startswith("0" * diff)
    print("  [PASSED] Transaksi berkas terenkripsi berhasil diikat ke dalam blok #2.")

    # -------------------------------------------------------------------------
    # UJI 4: PENCATATAN LOG AUDIT LOGIN PENGGUNA
    # -------------------------------------------------------------------------
    print("\n[UJI 4] Penambangan Blok Log Audit Login Pengguna")
    b_audit = bc.record_login_audit(
        actor="charlie",
        status="SUCCESS",
        factor_details={"dongle": "VALID", "face_match": "97.8%", "password": "VALID"}
    )
    print(f"  * Blok #{b_audit.index} Ditambang : Hash={b_audit.hash}")
    assert b_audit.index == 3
    assert b_audit.prev_hash == b_file.hash
    print("  [PASSED] Log audit keamanan berhasil diikat ke dalam blok #3.")

    # -------------------------------------------------------------------------
    # UJI 5: VALIDASI INTEGRITAS SELURUH RANTAI (VALIDATE_CHAIN)
    # -------------------------------------------------------------------------
    print("\n[UJI 5] Validasi Keutuhan Rantai (validate_chain)")
    is_valid, msg, broken_idx = bc.validate_chain()
    print(f"  * Status Valid : {is_valid}")
    print(f"  * Pesan        : {msg}")
    assert is_valid is True, "GAGAL: Rantai pada kondisi normal harus valid 100%!"
    assert broken_idx is None
    print("  [PASSED] Seluruh rantai 4 blok terverifikasi valid secara matematis.")

    # -------------------------------------------------------------------------
    # UJI 6: PERSISTENSI LEDGER PADA DISK (JSON STORAGE)
    # -------------------------------------------------------------------------
    print("\n[UJI 6] Pengujian Persistensi Ledger (Memuat Ulang dari Disk)")
    # Buat instance baru membaca file yang sama dari disk
    bc_reloaded = Blockchain(ledger_path=test_ledger_file, difficulty=diff)
    print(f"  * Jumlah Blok Terbaca dari Disk : {len(bc_reloaded.chain)}")
    assert len(bc_reloaded.chain) == 4, "GAGAL: Jumlah blok yang dimuat ulang tidak cocok!"
    rel_valid, rel_msg, _ = bc_reloaded.validate_chain()
    assert rel_valid is True, "GAGAL: Rantai yang dimuat ulang harus tetap valid!"
    print("  [PASSED] Persistensi JSON ledger berhasil memulihkan kondisi rantai secara utuh.")

    # -------------------------------------------------------------------------
    # UJI 7: SIMULASI SERANGAN MANIPULASI DATA (TAMPER ATTACK DETECTION)
    # -------------------------------------------------------------------------
    print("\n[UJI 7] Simulasi Serangan Manipulasi Data (Tamper Attack)")
    print("  * Penyerang mengubah pengirim pesan di Blok #1 dari 'alice' menjadi 'hacker_mallory'...")
    bc.tamper_block_for_testing(
        block_index=1,
        field_to_tamper="sender",
        fake_value="hacker_mallory"
    )
    
    # Jalankan verifikasi integritas
    tamper_valid, tamper_msg, corrupted_idx = bc.validate_chain()
    print(f"  * Hasil Audit Integritas : Valid={tamper_valid}, Blok Korup=#{corrupted_idx}")
    print(f"  * Pesan Kesalahan        : {tamper_msg}")
    
    assert tamper_valid is False, "GAGAL: Manipulasi data harus terdeteksi!"
    assert corrupted_idx == 1, "GAGAL: Sistem harus tepat mendeteksi bahwa Blok #1 yang dirusak!"
    print("  [PASSED] Serangan manipulasi data seketika terdeteksi berkat fungsi hash SHA-256.")

    print("\n" + "=" * 75)
    print(" SELURUH PENGUJIAN TAHAP 6 BERHASIL 100%! BLOCKCHAIN AUDIT TRAIL SIAP.")
    print("=" * 75)


if __name__ == "__main__":
    run_tests()

