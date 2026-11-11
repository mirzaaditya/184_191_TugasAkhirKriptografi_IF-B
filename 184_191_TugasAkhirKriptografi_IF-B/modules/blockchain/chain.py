"""
==============================================================================
MODUL: MESIN BLOCKCHAIN (POW SHA-256 & LEDGER AUDIT TRAIL)
==============================================================================
Deskripsi:
Modul ini mengimplementasikan buku besar terdistribusi sederhana (Blockchain)
menggunakan fungsi hash SHA-256 dan konsensus Proof-of-Work (PoW).

Fungsi Utama:
1. Immutability: Mengamankan bukti transaksi pesan, berkas, dan log audit login
   agar tidak dapat dihapus atau diubah secara retrospektif (*tamper-evident*).
2. Proof-of-Work (PoW): Memaksa komputasi matematis untuk setiap blok baru,
   sehingga penyerang membutuhkan komputasi masif jika ingin menulis ulang sejarah rantai.
3. Validasi Rantai (validate_chain): Memeriksa keutuhan hash setiap blok dan
   kevalidan rantai kriptografis (prev_hash) untuk mendeteksi manipulasi.
4. Persistensi JSON: Menyimpan seluruh ledger blok ke disk secara permanen.
==============================================================================
"""

import json
import datetime
from pathlib import Path
from config.settings import BLOCKCHAIN_LEDGER_PATH, BLOCKCHAIN_POW_DIFFICULTY
from modules.blockchain.block import Block


class Blockchain:
    """
    Pengelola rantai blok (Blockchain Ledger) untuk pencatatan audit log dan hash aset pesan/berkas.
    """

    def __init__(
        self,
        ledger_path: Path = BLOCKCHAIN_LEDGER_PATH,
        difficulty: int = BLOCKCHAIN_POW_DIFFICULTY
    ):
        self.ledger_path = Path(ledger_path)
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        self.difficulty = difficulty
        self.chain: list[Block] = []
        
        self.load_or_init_chain()

    def create_genesis_block(self) -> Block:
        """Membuat Blok Perdana (Genesis Block #0) sebagai jangkar awal rantai."""
        genesis_data = {
            "type": "GENESIS",
            "message": "Genesis Block - Secure Messenger Blockchain Ledger 2026",
            "creator": "SYSTEM",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        genesis_block = Block(
            index=0,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            data=genesis_data,
            prev_hash="0" * 64,
            nonce=0
        )
        genesis_block.mine_block(self.difficulty)
        return genesis_block

    def load_or_init_chain(self) -> None:
        """Memuat rantai dari berkas JSON di disk, atau membuat Genesis Block jika baru."""
        if self.ledger_path.exists():
            try:
                with open(self.ledger_path, "r", encoding="utf-8") as f:
                    raw_data = json.load(f)
                    self.chain = [Block.from_dict(b) for b in raw_data]
                    if len(self.chain) > 0:
                        return
            except Exception:
                self.chain = []
                
        # Jika belum ada rantai yang tersimpan, buat genesis block
        genesis = self.create_genesis_block()
        self.chain = [genesis]
        self.save_ledger()

    def save_ledger(self) -> None:
        """Menyimpan seluruh rantai blok ke berkas JSON di disk."""
        data_to_save = [b.to_dict() for b in self.chain]
        with open(self.ledger_path, "w", encoding="utf-8") as f:
            json.dump(data_to_save, f, indent=4)

    def get_latest_block(self) -> Block:
        """Mengambil blok terakhir di ujung rantai."""
        return self.chain[-1]

    def add_block(self, data: dict) -> Block:
        """
        Menambang (mine) blok baru dan menyambungkannya ke rantai.
        
        Args:
            data (dict): Data transaksi / log audit yang akan dicatat.
            
        Returns:
            Block: Blok baru yang berhasil ditambang dan diverifikasi.
        """
        latest = self.get_latest_block()
        new_block = Block(
            index=latest.index + 1,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            data=data,
            prev_hash=latest.hash,
            nonce=0
        )
        # Eksekusi Proof-of-Work
        new_block.mine_block(self.difficulty)
        
        self.chain.append(new_block)
        self.save_ledger()
        return new_block

    # =========================================================================
    # FUNGSI PENCATATAN TRANSAKSI SPESIFIK
    # =========================================================================
    def record_message_transaction(
        self,
        sender: str,
        recipient: str,
        message_hash: str,
        asset_type: str = "TEXT"
    ) -> Block:
        """
        Mencatat pengiriman pesan teks atau steganografi ke dalam blockchain.
        Menyimpan bukti hash SHA-256 dari konten pesan.
        """
        tx_data = {
            "record_type": "MESSAGE_TRANSACTION",
            "sender": sender.lower(),
            "recipient": recipient.lower(),
            "asset_type": asset_type.upper(),
            "message_hash": message_hash,
            "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        return self.add_block(tx_data)

    def record_file_transaction(
        self,
        sender: str,
        recipient: str,
        file_hash: str,
        filename: str
    ) -> Block:
        """
        Mencatat pengiriman berkas dokumen/biner ke dalam blockchain.
        """
        tx_data = {
            "record_type": "FILE_TRANSACTION",
            "sender": sender.lower(),
            "recipient": recipient.lower(),
            "filename": filename,
            "file_sha256": file_hash,
            "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        return self.add_block(tx_data)

    def record_login_audit(
        self,
        actor: str,
        status: str,
        factor_details: dict = None
    ) -> Block:
        """
        Mencatat log audit percobaan login (Sukses atau Ditolak) ke dalam blockchain.
        """
        audit_data = {
            "record_type": "LOGIN_AUDIT",
            "actor": actor.lower(),
            "status": status.upper(),
            "factor_details": factor_details or {},
            "audit_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        return self.add_block(audit_data)

    def record_message_event(
        self,
        event_type: str,
        actor: str,
        message_hash: str
    ) -> Block:
        """
        Mencatat event audit terkait pesan ke dalam blockchain.
        Hanya hash pesan dan username yang dicatat — TIDAK menyimpan password atau key.

        Args:
            event_type (str): 'MSG_RECEIVED', 'MSG_OPENED', atau 'MSG_OPEN_FAILED'.
            actor (str): Username penerima yang melakukan aksi.
            message_hash (str): SHA-256 hash pesan sebagai identifikator unik.

        Returns:
            Block: Blok baru yang berhasil ditambang.
        """
        event_data = {
            "record_type": "MESSAGE_EVENT",
            "event_type": event_type.upper(),
            "actor": actor.lower(),
            "message_hash": message_hash,
            "audit_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        return self.add_block(event_data)

    # =========================================================================
    # VALIDASI INTEGRITAS RANTAI BLOK (VALIDATE_CHAIN)
    # =========================================================================
    def validate_chain(self) -> tuple[bool, str, int | None]:
        """
        Memvalidasi keutuhan dan integritas matematis seluruh rantai blok:
        1. Memverifikasi apakah hash setiap blok cocok dengan hitungan ulang datanya.
        2. Memverifikasi apakah hash setiap blok memenuhi target Proof-of-Work (awalan nol).
        3. Memverifikasi apakah prev_hash setiap blok cocok persis dengan hash blok sebelumnya.
        
        Returns:
            tuple[bool, str, int | None]: (Status Valid, Pesan Deskripsi, Indeks Blok Korup jika ada)
        """
        target_prefix = "0" * self.difficulty
        
        for i, block in enumerate(self.chain):
            # 1. Verifikasi Konsensus Proof-of-Work
            if not block.hash.startswith(target_prefix):
                return (
                    False,
                    f"VALIDASI GAGAL: Blok #{block.index} tidak memenuhi syarat Proof-of-Work "
                    f"(hash '{block.hash[:10]}...' tidak diawali '{target_prefix}').",
                    block.index
                )
                
            # 2. Verifikasi Integritas Data Internal Blok
            recalculated_hash = block.calculate_hash()
            if block.hash != recalculated_hash:
                return (
                    False,
                    f"MANIPULASI TERDETEKSI pada Blok #{block.index}! Hash tersimpan ({block.hash[:16]}...) "
                    f"tidak cocok dengan hasil hitung ulang data ({recalculated_hash[:16]}...). "
                    f"Data blok terbukti telah diubah!",
                    block.index
                )
                
            # 3. Verifikasi Tautan Rantai Kriptografis (Prev Hash)
            if i > 0:
                previous_block = self.chain[i - 1]
                if block.prev_hash != previous_block.hash:
                    return (
                        False,
                        f"RANTAI PUTUS pada Blok #{block.index}! prev_hash ({block.prev_hash[:16]}...) "
                        f"tidak menyambung ke hash blok sebelumnya #{previous_block.index} ({previous_block.hash[:16]}...).",
                        block.index
                    )
                    
        return (
            True,
            f"SELURUH RANTAI VALID: {len(self.chain)} blok terverifikasi utuh tanpa ada manipulasi data.",
            None
        )

    def tamper_block_for_testing(self, block_index: int, field_to_tamper: str, fake_value: str) -> None:
        """
        Fungsi bantuan demonstrasi: Sengaja memodifikasi data di dalam blok tertentu
        untuk membuktikan kepada dosen bahwa validate_chain() mampu mendeteksi manipulasi data seketika.
        """
        if 0 <= block_index < len(self.chain):
            self.chain[block_index].data[field_to_tamper] = fake_value
            # Simpan data yang dimanipulasi tanpa menambang ulang hash
            self.save_ledger()

