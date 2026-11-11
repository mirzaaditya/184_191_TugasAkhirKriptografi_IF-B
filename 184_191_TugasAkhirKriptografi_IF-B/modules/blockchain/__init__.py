"""
Inisialisasi Modul Blockchain:
- block: Representasi struktur data blok rantai tunggal
- chain: Mesin Blockchain dengan Proof-of-Work SHA-256, persistensi ledger JSON, dan validator integritas
"""
from modules.blockchain.block import Block
from modules.blockchain.chain import Blockchain

__all__ = ["Block", "Blockchain"]

