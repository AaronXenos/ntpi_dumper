# Executive Summary: NTPI v1.2.1 Reverse Engineering & Extraction

## Objective

Add full support for **NTPI firmware version 1.2.1** to `ntpi_dumper`, including AES key extraction, header format handling, and memory-optimized extraction for multi-GB firmware files.

---

## Methodology

### Phase 1: Dynamic Analysis Attempts (Failed)

**Goal:** Extract AES-256-CBC keys at runtime from `NothingFlashTool.exe` (12 MB, x86).

| Approach | Tool | Result |
|----------|------|--------|
| Memory dump + entropy scan | x32dbg | Partial keys, unreliable (heuristic) |
| AES-NI instruction breakpoints | x32dbg / aesfinder | Crashes (embedded OpenSSL CRYPTOGAMS interferes) |
| Frida hooking (OpenSSL EVP) | Frida | Process exits before hooks attach |
| USB sniffing / BadUSB | Arduino / ESP32 | Not applicable (encryption is local) |

**Conclusion:** Dynamic analysis was unreliable for this target. Pivoted to static analysis.

### Phase 2: Static Analysis via IDA Pro (Successful)

**Goal:** Statically trace the AES key material in the disassembled binary.

1. **Loaded `NothingFlashTool.exe`** into IDA Pro (x86, 12,378,112 bytes)
2. **Identified OpenSSL EVP usage** by searching for `EVP_DecryptInit_ex`, `EVP_CIPHER` structures
3. **Confirmed cipher:** AES-256-CBC via `EVP_CIPHER` struct at the call site
   - NID = 427 → AES-256-CBC
   - key_len = 32, iv_len = 16, block_size = 16
4. **Traced key function `sub_4A2F60`** ("ExtractRegionData"):
   - This function handles decryption for each firmware region (1–5)
   - Each region uses a **different hardcoded key/IV pair** loaded from `.rdata`
   - Key material located at `.rdata` offsets `0x7936C4`–`0x7937D0`
5. **Extracted all 5 region key/IV pairs** directly from the `.rdata` section
6. **Validated:** Region 1 decrypts to valid `<Metadata>` XML → keys confirmed correct

### Phase 3: Header Format Reverse Engineering

**Discovery:** NTPI v1.2.1 uses a **40-byte header** (vs. 48 bytes in v1.3.0).

| Field | v1.2.1 (40 bytes) | v1.3.0 (48 bytes) |
|-------|--------------------|--------------------|
| Magic | `NTPI` (4 bytes) | `NTPI` (4 bytes) |
| Padding | 4 bytes | 4 bytes |
| Version (major/minor/patch) | 3 × uint64 (24 bytes) | 3 × uint64 (24 bytes) |
| First region | enc_size only (8 bytes) | region_type + region_size (16 bytes) |
| **Data offset** | **40** | **48** |

In v1.2.1, the `region_type` is not present in the header—it is embedded inside the encrypted `RegionBlockHeader`. Regions always appear sequentially (1, 2, 3, 4, 5, 6), so the parser uses a sequential index for key selection.

### Phase 4: Memory Optimization (mmap)

**Problem:** Stage 2 processes Region 6 (~3.7 GB). The original code loaded the entire file into memory and pickled it to each worker process via `multiprocessing.Pool`, causing >15 GB memory usage and crashes.

**Solution:** Replaced `f.read()` with `mmap.mmap(ACCESS_READ)`:
- Each worker opens its own read-only memory-mapped view
- The OS deduplicates physical memory pages across processes
- No pickle/copy of multi-GB data between processes
- KeyMap (~4 KB) is still loaded into memory per worker (negligible)

**Result:** Memory usage dropped from >15 GB to ~500 MB. All 59 files extracted in **2.3 minutes** with full SHA256 verification.

---

## Changes Summary

### `utils/structures.py`
- Added `AESDICT_IDA_EXTRACT`: 5 AES-256-CBC key/IV pairs from IDA Pro analysis
- Added `AESDICT_V1_2_1_MEMDUMP`: Earlier memory-dump keys (kept for reference)
- Updated `VERSION_KEY_MAP` to map v1.2.1 → `AESDICT_IDA_EXTRACT`

### `utils/parser.py`
- Added v1.2.1 header detection (40-byte header, data at offset 40)
- Added `key_region_index` parameter for sequential key selection
- Creates synthetic `RegionHeader` when `region_type` is not in header

### `utils/extractor.py`
- Replaced `f.read()` with `mmap.mmap(ACCESS_READ)` for Region 6
- Workers receive file paths (strings) instead of multi-GB data blobs
- Each worker opens its own mmap view; OS handles page sharing
- Added `G_REGION6_FILE` global for file handle lifetime management

### `README.md`
- Updated supported versions: v1.2.1 now fully supported
- Updated known limitations and contribution requests

### Deleted: `ntpi_dumper_go_version/`
- Removed Go/CGO version (no longer maintained, Python version is canonical)

---

## Validation

| Metric | Result |
|--------|--------|
| Files extracted | 59/59 |
| SHA256 verification | All pass |
| Extraction time | 2.3 minutes |
| Memory usage | ~500 MB (down from >15 GB) |
| Throughput | ~25–30 MB/s |

---

## Tools Used

- **IDA Pro** (static analysis of NothingFlashTool.exe)
- **x32dbg** (initial dynamic analysis attempts)
- **Python 3.14** + PyCryptodome (AES decryption)
- **mmap** (memory-mapped I/O for large files)
- **multiprocessing** + **ThreadPoolExecutor** (parallel extraction)
