## feat: Full NTPI v1.2.1 support + mmap memory optimization

### Summary

This PR adds complete support for **NTPI firmware version 1.2.1** and optimizes memory usage for large firmware extraction via memory-mapped I/O.

### What Changed

#### 🔑 AES Key Extraction (v1.2.1)
- Extracted all 5 region AES-256-CBC key/IV pairs via **IDA Pro static analysis** of `NothingFlashTool.exe`
- Keys sourced from `sub_4A2F60` ("ExtractRegionData") → `.rdata` section
- Cipher confirmed: AES-256-CBC (OpenSSL EVP NID 427)
- All keys validated: Region 1 decrypts to valid `<Metadata>` XML

#### 📐 v1.2.1 Header Format Support
- v1.2.1 uses a **40-byte header** (vs. 48 bytes in v1.3.0)
- No `region_type` in header — regions appear sequentially (1→6)
- Parser detects version and handles both formats transparently

#### ⚡ mmap Memory Optimization
- Replaced `f.read()` + multiprocessing pickle with per-worker `mmap.mmap(ACCESS_READ)`
- Memory usage: **~500 MB** (down from >15 GB for 3.7 GB firmware)
- OS shares physical memory pages across all worker processes

#### 🗑️ Removed Go/CGO Version
- Deleted `ntpi_dumper_go_version/` — Python version is the canonical implementation

### Files Changed

| File | Change |
|------|--------|
| `utils/structures.py` | Added `AESDICT_IDA_EXTRACT` (5 key/IV pairs), updated `VERSION_KEY_MAP` |
| `utils/parser.py` | v1.2.1 40-byte header support, sequential key indexing |
| `utils/extractor.py` | mmap refactor for Region 6 access |
| `README.md` | v1.2.1 marked fully supported, updated limitations |
| `.gitignore` | Exclude research/scratch files from tracking |
| `ntpi_dumper_go_version/` | **Deleted** |

### Validation

| Metric | Result |
|--------|--------|
| Files extracted | **59/59** |
| SHA256 verification | **All pass** ✅ |
| Extraction time | **2.3 minutes** |
| Memory usage | **~500 MB** |
| Throughput | **~25–30 MB/s** |

### Methodology

See [EXECUTIVE_SUMMARY.md](EXECUTIVE_SUMMARY.md) for the full reverse engineering methodology, including:
- IDA Pro analysis trace from OpenSSL EVP → AES-256-CBC → per-region keys
- Header format comparison (v1.2.1 vs v1.3.0)
- mmap optimization rationale

### Testing

Tested against a real NTPI v1.2.1 firmware file:
- All 59 files extracted successfully
- All SHA256 hashes verified against `FileIndex.xml`
- 4 large files (super_3/4/5/6.img, >500 MB each) processed with parallel segmentation
