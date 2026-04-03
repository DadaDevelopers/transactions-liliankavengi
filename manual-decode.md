# Manual Transaction Decode

## Raw Hex
```
0200000000010131811cd355c357e0e01437d9bcf690df824e9ff785012b6115dfae3d8e8b36c10100000000fdffffff0220a107000000000016001485d78eb795bd9c8a21afefc8b6fdaedf718368094c08100000000000160014840ab165c9c2555d4a31b9208ad806f89d2535e20247304402207bce86d430b58bb6b79e8c1bbecdf67a530eff3bc61581a1399e0b28a741c0ee0220303d5ce926c60bf15577f2e407f28a2ef8fe8453abd4048b716e97dbb1e3a85c01210260828bc77486a55e3bc6032ccbeda915d9494eda17b4a54dbe3b24506d40e4ff43030e00
```

---

## Byte-by-Byte Breakdown

| Field | Raw Bytes (hex) | Decoded Value |
|-------|----------------|---------------|
| Version | `02000000` | 2 (little-endian) |
| Marker | `00` | SegWit marker |
| Flag | `01` | SegWit flag |
| Input Count | `01` | 1 input |
| Prev TX Hash | `31811cd355c357e0e01437d9bcf690df824e9ff785012b6115dfae3d8e8b36c1` | (reversed below) |
| Prev Output Index | `01000000` | 1 (little-endian) |
| ScriptSig Length | `00` | 0 bytes (empty — SegWit) |
| ScriptSig | *(empty)* | — |
| Sequence | `fdffffff` | 0xfffffffd |
| Output Count | `02` | 2 outputs |
| Output 1 Amount | `20a10700 00000000` | 500,000 satoshis |
| Output 1 Script Len | `16` | 22 bytes |
| Output 1 ScriptPubKey | `001485d78eb795bd9c8a21afefc8b6fdaedf71836809` | P2WPKH |
| Output 2 Amount | `4c081000 00000000` | 1,050,700 satoshis |
| Output 2 Script Len | `16` | 22 bytes |
| Output 2 ScriptPubKey | `0014840ab165c9c2555d4a31b9208ad806f89d2535e2` | P2WPKH |
| Witness Stack Items | `02` | 2 items |
| Witness Item 1 Len | `47` | 71 bytes |
| Witness Item 1 | `304402207bce86d430b58bb6b79e8c1bbecdf67a530eff3bc61581a1399e0b28a741c0ee0220303d5ce926c60bf15577f2e407f28a2ef8fe8453abd4048b716e97dbb1e3a85c01` | DER Signature + SIGHASH_ALL |
| Witness Item 2 Len | `21` | 33 bytes |
| Witness Item 2 | `0260828bc77486a55e3bc6032ccbeda915d9494eda17b4a54dbe3b24506d40e4ff` | Compressed Public Key |
| Locktime | `43030e00` | 918,339 (little-endian) |

---

## Structured Decode

```
=== Manual Transaction Decode ===

Version: 2
Marker: 00
Flag: 01

Input Count: 1

Input #1:
  Previous TX Hash: c1368b8e3daedf15612b0185f79f4e82df90f6bcd93714e0e057c355d31c8131
  Previous Output Index: 1
  Script Length: 0
  ScriptSig: (empty)
  Sequence: fdffffff

Output Count: 2

Output #1:
  Amount (satoshis): 500,000
  Script Length: 22
  ScriptPubKey: 001485d78eb795bd9c8a21afefc8b6fdaedf71836809

Output #2:
  Amount (satoshis): 1,050,700
  Script Length: 22
  ScriptPubKey: 0014840ab165c9c2555d4a31b9208ad806f89d2535e2

Witness Data:
  Input #1:
    Stack items: 2
    Item 1 (71 bytes): 304402207bce86d430b58bb6b79e8c1bbecdf67a530eff3bc61581a1399e0b28a741c0ee0220303d5ce926c60bf15577f2e407f28a2ef8fe8453abd4048b716e97dbb1e3a85c01
    Item 2 (33 bytes): 0260828bc77486a55e3bc6032ccbeda915d9494eda17b4a54dbe3b24506d40e4ff

Locktime: 918339
```

---

## Notes

- **Transaction Type:** Native SegWit (P2WPKH) — detected by `marker=00` and `flag=01` bytes after version
- **Previous TXID:** The raw hash bytes are reversed (Bitcoin displays TXIDs in reverse byte order): `31811cd3...` → `c1368b8e...`
- **ScriptSig is empty** because the spending script is moved to the witness field in SegWit
- **Both outputs are P2WPKH** — identified by the `0014` prefix (OP_0 + 20-byte push)
- **Witness Item 1** is a DER-encoded ECDSA signature with `01` SIGHASH_ALL suffix
- **Witness Item 2** is a 33-byte compressed public key (prefix `02` = even Y-coordinate)
- **Sequence `fdffffff`** = `0xFFFFFFFD` — enables RBF (Replace-By-Fee), which is one less than `0xFFFFFFFE`
- **Locktime 918,339** is a block height, meaning this transaction cannot be mined before block 918,339
