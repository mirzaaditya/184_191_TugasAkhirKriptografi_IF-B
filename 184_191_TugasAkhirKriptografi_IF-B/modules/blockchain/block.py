"""
==============================================================================
MODUL: STRUKTUR DATA BLOK (BLOCK ENTITY)
==============================================================================
Deskripsi:
Mendefinisikan entitas tunggal sebuah blok di dalam Blockchain.
Setiap blok menyimpan:
1. `index`: Nomor urut blok (0 = Genesis Block).
2. `timestamp`: Waktu pembuatan blok (ISO 8601 UTC).
3. `data`: Muatan transaksi (hash SHA-256 pesan, hash berkas, atau log audit login).
4. `prev_hash`: Hash SHA-256 dari blok sebelumnya (membentuk tautan rantai kriptografis).
5. `nonce`: Angka acak / pencacah Proof-of-Work (PoW).
6. `hash`: Hash SHA-256 dari seluruh isi blok saat memenuhi target PoW.
==============================================================================
"""

import json
import hashlib
import datetime


class Block:
    """
    Kelas yang merepresentasikan satu blok dalam buku besar (ledger) rantai blok.
    """

    def __init__(
        self,
        index: int,
        timestamp: str,
        data: dict,
        prev_hash: str,
        nonce: int = 0,
        block_hash: str = None
    ):
        self.index = index
        self.timestamp = timestamp or datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.data = data
        self.prev_hash = prev_hash
        self.nonce = nonce
        self.hash = block_hash or self.calculate_hash()

    def calculate_hash(self) -> str:
        """
        Menghitung nilai hash SHA-256 kanonikal dari seluruh komponen isi blok.
        Menggunakan json.dumps dengan sort_keys=True agar representasi data selalu deterministik.
        """
        canonical_data = json.dumps(self.data, sort_keys=True)
        block_string = f"{self.index}|{self.timestamp}|{canonical_data}|{self.prev_hash}|{self.nonce}"
        return hashlib.sha256(block_string.encode("utf-8")).hexdigest()

    def mine_block(self, difficulty: int) -> int:
        """
        Menjalankan algoritma Proof-of-Work (PoW):
        Mencari nilai nonce sedemikian rupa sehingga hash blok diawali oleh sejumlah nol
        sesuai tingkat kesulitan (difficulty).
        
        Args:
            difficulty (int): Jumlah karakter nol pembuka (misal 2 -> '00...').
            
        Returns:
            int: Jumlah iterasi penambangan yang dilakukan.
        """
        target_prefix = "0" * difficulty
        iterations = 0
        
        while not self.hash.startswith(target_prefix):
            self.nonce += 1
            self.hash = self.calculate_hash()
            iterations += 1
            
        return iterations

    def to_dict(self) -> dict:
        """Serialisasi objek blok ke dalam format dictionary JSON."""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "prev_hash": self.prev_hash,
            "nonce": self.nonce,
            "hash": self.hash
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Block":
        """Rekonstruksi objek blok dari dictionary."""
        return cls(
            index=d["index"],
            timestamp=d["timestamp"],
            data=d["data"],
            prev_hash=d["prev_hash"],
            nonce=d.get("nonce", 0),
            block_hash=d.get("hash")
        )

    def __repr__(self) -> str:
        return f"<Block #{self.index} [Hash: {self.hash[:12]}...] Prev: {self.prev_hash[:12]}...>"

