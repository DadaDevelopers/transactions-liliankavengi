[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/LEq9uTEL)
# assignment-3

# Bitcoin Transaction Decoding Assignment

## Transaction Hex

```
0200000000010131811cd355c357e0e01437d9bcf690df824e9ff785012b6115dfae3d8e8b36c10100000000fdffffff0220a107000000000016001485d78eb795bd9c8a21afefc8b6fdaedf718368094c08100000000000160014840ab165c9c2555d4a31b9208ad806f89d2535e20247304402207bce86d430b58bb6b79e8c1bbecdf67a530eff3bc61581a1399e0b28a741c0ee0220303d5ce926c60bf15577f2e407f28a2ef8fe8453abd4048b716e97dbb1e3a85c01210260828bc77486a55e3bc6032ccbeda915d9494eda17b4a54dbe3b24506d40e4ff43030e00
```

**Transaction Details:** [View on mempool.space](https://mempool.space/tx/04f487fe9754a925c2e96492afeab47e7c839d0582eef80b3ecc9ca3afa05842)

---

## Task 1: Manually Decode the Transaction

Decode the transaction hex manually and identify all components.

### Required Fields to Identify:

1. **Version**
2. **Marker and Flag** (for SegWit transactions)
3. **Input Count**
4. **Inputs:**
   - Previous transaction hash (txid)
   - Previous output index (vout)
   - Script length
   - ScriptSig
   - Sequence number
5. **Output Count**
6. **Outputs:**
   - Amount (in satoshis)
   - Script length
   - ScriptPubKey
7. **Witness Data** (for SegWit transactions)
8. **Locktime**

### Submission Format:

```
=== Manual Transaction Decode ===

Version: [your answer]
Marker: [your answer]
Flag: [your answer]

Input Count: [your answer]

Input #1:
  Previous TX Hash: [your answer]
  Previous Output Index: [your answer]
  Script Length: [your answer]
  ScriptSig: [your answer]
  Sequence: [your answer]

Output Count: [your answer]

Output #1:
  Amount (satoshis): [your answer]
  Script Length: [your answer]
  ScriptPubKey: [your answer]

Output #2:
  Amount (satoshis): [your answer]
  Script Length: [your answer]
  ScriptPubKey: [your answer]

Witness Data:
  [your answer]

Locktime: [your answer]
```

---

## Task 2: Write a Transaction Decoder Function

Write a function (or set of functions) in any programming language that can decode any given Bitcoin transaction hex.

### Requirements:

- Accept transaction hex as input
- Parse and decode all transaction components
- Handle both legacy and SegWit transactions
- Output structured transaction data
- Test with the provided transaction hex
- Share the complete output

### Suggested Structure:

```python
def decode_transaction(hex_string):
    """
    Decode a Bitcoin transaction from hex format
    
    Args:
        hex_string: Raw transaction hex
        
    Returns:
        Dictionary containing decoded transaction data
    """
    # Your implementation here
    pass

# Test with provided transaction
tx_hex = "0200000000010131811cd355c357e0e01437d9bcf690df824e9ff785012b6115dfae3d8e8b36c10100000000fdffffff0220a107000000000016001485d78eb795bd9c8a21afefc8b6fdaedf718368094c08100000000000160014840ab165c9c2555d4a31b9208ad806f89d2535e20247304402207bce86d430b58bb6b79e8c1bbecdf67a530eff3bc61581a1399e0b28a741c0ee0220303d5ce926c60bf15577f2e407f28a2ef8fe8453abd4048b716e97dbb1e3a85c01210260828bc77486a55e3bc6032ccbeda915d9494eda17b4a54dbe3b24506d40e4ff43030e00"

decoded = decode_transaction(tx_hex)
print(decoded)
```

### Output Format:

Your function should output something like:

```json
{
  "version": 2,
  "marker": "00",
  "flag": "01",
  "inputs": [
    {
      "txid": "...",
      "vout": 1,
      "scriptSig": "...",
      "sequence": "..."
    }
  ],
  "outputs": [
    {
      "amount": 500000,
      "scriptPubKey": "..."
    },
    {
      "amount": 1050700,
      "scriptPubKey": "..."
    }
  ],
  "witness": [...],
  "locktime": 921411
}
```

---

## Submission Guidelines

Submit the following:

```
📁 transaction-decoding-assignment/
├── manual-decode.md (Task 1: Manual decoding)
├── decoder.py (or .js, .go, etc.)
├── output.txt (Program output)
└── README.md (Documentation explaining your code)
```

---

## Tips

- Remember Bitcoin uses little-endian byte order for most fields
- SegWit transactions have marker `00` and flag `01` after version
- VarInt encoding is used for counts and lengths
- Amounts are in satoshis (1 BTC = 100,000,000 satoshis)
- Compare your results with the mempool.space link to verify accuracy
