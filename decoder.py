"""
Bitcoin Transaction Decoder
============================
Decodes raw Bitcoin transaction hex into structured components.
Supports both Legacy and SegWit (marker/flag) transaction formats.
"""

import json
import struct


# Low-level reader

class ByteReader:
    """Stateful reader that advances a cursor through a bytes object."""

    def __init__(self, raw: bytes):
        self.data = raw
        self.pos = 0

    def read(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError(
                f"Not enough bytes: need {n} at pos {self.pos}, "
                f"only {len(self.data) - self.pos} remaining"
            )
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def read_varint(self) -> int:
        """
        Read a Bitcoin variable-length integer (VarInt).
        Encoding:
          < 0xFD          → 1 byte
          0xFD            → next 2 bytes (little-endian)
          0xFE            → next 4 bytes (little-endian)
          0xFF            → next 8 bytes (little-endian)
        """
        first = self.data[self.pos]
        self.pos += 1
        if first < 0xFD:
            return first
        elif first == 0xFD:
            return int.from_bytes(self.read(2), "little")
        elif first == 0xFE:
            return int.from_bytes(self.read(4), "little")
        else:  # 0xFF
            return int.from_bytes(self.read(8), "little")

    def remaining(self) -> int:
        return len(self.data) - self.pos



# Helper utilities

def le_to_int(raw: bytes) -> int:
    """Convert little-endian bytes to an integer."""
    return int.from_bytes(raw, "little")


def reverse_hex(raw: bytes) -> str:
    """
    Reverse bytes and return hex string.
    Used for TXIDs: Bitcoin stores them internally in little-endian order
    but displays them reversed (big-endian) on block explorers.
    """
    return raw[::-1].hex()


def classify_script(script_hex: str) -> str:
    """
    Identify common scriptPubKey types from the hex representation.
    """
    s = script_hex
    if s.startswith("0014") and len(s) == 44:
        return "P2WPKH (Pay-to-Witness-Public-Key-Hash)"
    if s.startswith("0020") and len(s) == 68:
        return "P2WSH (Pay-to-Witness-Script-Hash)"
    if s.startswith("76a914") and s.endswith("88ac") and len(s) == 50:
        return "P2PKH (Pay-to-Public-Key-Hash)"
    if s.startswith("a914") and s.endswith("87") and len(s) == 46:
        return "P2SH (Pay-to-Script-Hash)"
    if s.startswith("5120") and len(s) == 68:
        return "P2TR (Pay-to-Taproot)"
    if len(s) in (66, 130) and s.endswith("ac"):
        return "P2PK (Pay-to-Public-Key)"
    if s == "6a":
        return "OP_RETURN (data carrier)"
    return "Unknown"



# Core decoder

def decode_transaction(hex_string: str) -> dict:
    """
    Decode a raw Bitcoin transaction from its hex representation.

    Args:
        hex_string: Raw transaction hex string (with or without whitespace).

    Returns:
        A dictionary with all decoded transaction fields:
          version, marker, flag, inputs, outputs, witness, locktime,
          txid (legacy), wtxid (segwit), and is_segwit flag.
    """
    raw = bytes.fromhex(hex_string.strip())
    reader = ByteReader(raw)

    result = {}

    # 1. VERSION  (4 bytes, little-endian)

    version_bytes = reader.read(4)
    result["version"] = le_to_int(version_bytes)

    # 2. SEGWIT DETECTION
    # Peek at the next two bytes.  If they are 0x00 0x01, this is a
    # SegWit transaction (BIP141 serialisation format).

    peek_marker = raw[reader.pos]
    peek_flag   = raw[reader.pos + 1]
    is_segwit   = (peek_marker == 0x00 and peek_flag == 0x01)
    result["is_segwit"] = is_segwit

    if is_segwit:
        marker_byte = reader.read(1)
        flag_byte   = reader.read(1)
        result["marker"] = marker_byte.hex()   # "00"
        result["flag"]   = flag_byte.hex()      # "01"
    else:
        result["marker"] = None
        result["flag"]   = None

  
    # 3. INPUT COUNT  (VarInt)

    input_count = reader.read_varint()
    result["input_count"] = input_count


    # 4. INPUTS
   
    inputs = []
    for _ in range(input_count):
        prev_hash_raw = reader.read(32)          # 32 bytes, stored little-endian
        vout_bytes    = reader.read(4)
        script_len    = reader.read_varint()
        scriptsig_raw = reader.read(script_len)
        seq_bytes     = reader.read(4)

        inp = {
            "txid": reverse_hex(prev_hash_raw),      # reversed for display
            "txid_raw_le": prev_hash_raw.hex(),       # as stored in raw bytes
            "vout": le_to_int(vout_bytes),
            "script_length": script_len,
            "scriptSig": scriptsig_raw.hex() if script_len > 0 else "",
            "sequence": seq_bytes.hex(),
            "sequence_int": le_to_int(seq_bytes),
        }
        inputs.append(inp)

    result["inputs"] = inputs
   
    # 5. OUTPUT COUNT  (VarInt)

    output_count = reader.read_varint()
    result["output_count"] = output_count

    # 6. OUTPUTS
    
    outputs = []
    for _ in range(output_count):
        amount_bytes = reader.read(8)
        script_len   = reader.read_varint()
        script_raw   = reader.read(script_len)

        script_hex = script_raw.hex()
        out = {
            "amount_satoshis": le_to_int(amount_bytes),
            "amount_btc": le_to_int(amount_bytes) / 1e8,
            "script_length": script_len,
            "scriptPubKey": script_hex,
            "script_type": classify_script(script_hex),
        }
        outputs.append(out)

    result["outputs"] = outputs

    # 7. WITNESS DATA  (only present in SegWit transactions)
    # One witness stack per input, in the same order as the inputs.
  
    witness = []
    if is_segwit:
        for _ in range(input_count):
            stack_item_count = reader.read_varint()
            stack = []
            for _ in range(stack_item_count):
                item_len = reader.read_varint()
                item     = reader.read(item_len)
                stack.append({
                    "length": item_len,
                    "data": item.hex(),
                })
            witness.append(stack)
    result["witness"] = witness


    # 8. LOCKTIME  (4 bytes, little-endian)

    locktime_bytes   = reader.read(4)
    result["locktime"] = le_to_int(locktime_bytes)

    # Sanity check
    if reader.remaining() != 0:
        raise ValueError(
            f"Decode finished but {reader.remaining()} bytes remain unconsumed. "
            "The input may be malformed."
        )

    return result



# Pretty-printer

def print_decoded(tx: dict) -> None:
    """Print a decoded transaction in a human-readable format."""
    sep = "=" * 60

    print(sep)
    print("DECODED BITCOIN TRANSACTION")
    print(sep)
    print(f"  Version   : {tx['version']}")
    print(f"  SegWit    : {tx['is_segwit']}")
    if tx["is_segwit"]:
        print(f"  Marker    : {tx['marker']}")
        print(f"  Flag      : {tx['flag']}")

    print()
    print(f"  Inputs    : {tx['input_count']}")
    for i, inp in enumerate(tx["inputs"]):
        print(f"\n  ── Input #{i + 1}")
        print(f"     Previous TXID   : {inp['txid']}")
        print(f"     Previous Vout   : {inp['vout']}")
        print(f"     ScriptSig Len   : {inp['script_length']}")
        print(f"     ScriptSig       : {inp['scriptSig'] or '(empty — SegWit)'}")
        print(f"     Sequence        : {inp['sequence']}  ({inp['sequence_int']})")

    print()
    print(f"  Outputs   : {tx['output_count']}")
    for i, out in enumerate(tx["outputs"]):
        print(f"\n  ── Output #{i + 1}")
        print(f"     Amount          : {out['amount_satoshis']:,} satoshis  ({out['amount_btc']:.8f} BTC)")
        print(f"     ScriptPubKey Len: {out['script_length']}")
        print(f"     ScriptPubKey    : {out['scriptPubKey']}")
        print(f"     Script Type     : {out['script_type']}")

    if tx["is_segwit"] and tx["witness"]:
        print()
        print("  Witness Data:")
        for i, stack in enumerate(tx["witness"]):
            print(f"\n  ── Input #{i + 1} witness")
            if not stack:
                print("     (empty stack)")
            for j, item in enumerate(stack):
                print(f"     Item {j + 1}  ({item['length']} bytes): {item['data']}")

    print()
    print(f"  Locktime  : {tx['locktime']}")
    print(sep)



# Entry point

if __name__ == "__main__":
    tx_hex = (
        "0200000000010131811cd355c357e0e01437d9bcf690df824e9ff785012b6115dfae3d"
        "8e8b36c10100000000fdffffff0220a107000000000016001485d78eb795bd9c8a21af"
        "efc8b6fdaedf718368094c08100000000000160014840ab165c9c2555d4a31b9208ad8"
        "06f89d2535e20247304402207bce86d430b58bb6b79e8c1bbecdf67a530eff3bc61581"
        "a1399e0b28a741c0ee0220303d5ce926c60bf15577f2e407f28a2ef8fe8453abd4048b"
        "716e97dbb1e3a85c01210260828bc77486a55e3bc6032ccbeda915d9494eda17b4a54d"
        "be3b24506d40e4ff43030e00"
    )

    print("\n[1] Running decoder on provided transaction...\n")
    decoded = decode_transaction(tx_hex)

    # Human-readable output
    print_decoded(decoded)

    # JSON output
    print("\n[2] JSON representation:\n")
    print(json.dumps(decoded, indent=2))
