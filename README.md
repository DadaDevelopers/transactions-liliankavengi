# Bitcoin Transaction Decoder

A from-scratch Python decoder for raw Bitcoin transaction hex, supporting both **Legacy** and **SegWit** transaction formats.

---

## Files

| File | Purpose |
|------|---------|
| `manual-decode.md` | Hand-traced byte-by-byte decode of the assignment transaction |
| `decoder.py` | Full Python decoder — no external dependencies |
| `output.txt` | Console output from running `decoder.py` |
| `README.md` | This file |

---

## Usage

```bash
python3 decoder.py
```

No third-party libraries required — only the Python standard library (`json`, `struct`).

To decode a different transaction, change the `tx_hex` string at the bottom of `decoder.py`, or import and call the function directly:

```python
from decoder import decode_transaction, print_decoded

result = decode_transaction("YOUR_TX_HEX_HERE")
print_decoded(result)
```

---

## How It Works

### ByteReader

A stateful cursor over the raw bytes. Two key methods:

- **`read(n)`** — reads exactly `n` bytes and advances the cursor
- **`read_varint()`** — reads a Bitcoin variable-length integer

### VarInt Encoding

Bitcoin encodes counts and lengths with a compact variable-length integer:

| First byte | Extra bytes | Max value |
|------------|-------------|-----------|
| `< 0xFD` | 0 | 252 |
| `0xFD` | 2 | 65,535 |
| `0xFE` | 4 | 4,294,967,295 |
| `0xFF` | 8 | 2^64 − 1 |

### SegWit Detection

After reading the 4-byte version, the decoder peeks at the next two bytes. If they are `0x00 0x01`, the transaction uses the SegWit serialisation format (BIP141), and the decoder reads the marker/flag pair before continuing.

### Little-Endian Fields

Most multi-byte integers in Bitcoin are stored in little-endian order:
- Version, vout, amount, locktime → read with `int.from_bytes(b, "little")`
- TXID bytes are reversed for display — block explorers show them big-endian

### Witness Data

In SegWit transactions, after all outputs there is one witness stack per input. Each stack has a VarInt item-count, then each item has a VarInt length followed by that many bytes.

---

## Decoded Transaction Summary

| Field | Value |
|-------|-------|
| Version | 2 |
| Type | Native SegWit (P2WPKH) |
| Marker / Flag | `00` / `01` |
| Inputs | 1 |
| Previous TXID | `c1368b8e3daedf15612b0185f79f4e82df90f6bcd93714e0e057c355d31c8131` |
| Previous Vout | 1 |
| ScriptSig | *(empty — witness used instead)* |
| Sequence | `fdffffff` (RBF enabled) |
| Outputs | 2 |
| Output 1 | 500,000 sat → P2WPKH |
| Output 2 | 1,050,700 sat → P2WPKH |
| Witness Item 1 | 71-byte DER signature (SIGHASH_ALL) |
| Witness Item 2 | 33-byte compressed public key |
| Locktime | 918,339 |

---

## Script Type Classification

`classify_script()` identifies common output script types by their byte patterns:

| Prefix | Type |
|--------|------|
| `0014` + 20 bytes | P2WPKH |
| `0020` + 32 bytes | P2WSH |
| `76a914…88ac` | P2PKH |
| `a914…87` | P2SH |
| `5120` + 32 bytes | P2TR (Taproot) |

---

## Verification

Results were cross-checked against [mempool.space](https://mempool.space).
