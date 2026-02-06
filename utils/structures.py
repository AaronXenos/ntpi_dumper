"""
NTPI File Structure Definitions
Contains all ctypes structure definitions for parsing NTPI files.

Supported NTPI Versions:
- Version 1.2.1: Structure defined, AES keys pending extraction from imageChecker.dll
- Version 1.3.0: Fully supported with verified AES keys

Note: AES keys must be extracted via reverse engineering (IDA Pro).
      Never fabricate or guess cryptographic material.
"""
import ctypes


class RegionHeader(ctypes.Structure):
    """Header for each region in the NTPI file"""
    _fields_ = [
        ("region_type", ctypes.c_uint64),
        ("region_size", ctypes.c_uint64),
    ]


class NTPIHeader(ctypes.Structure):
    """Main NTPI file header"""
    _fields_ = [
        ("magic", ctypes.c_char * 4),
        ("padding", ctypes.c_uint32),
        ("version_major", ctypes.c_uint64),
        ("version_minor", ctypes.c_uint64),
        ("version_patch", ctypes.c_uint64),
        ("first_region_header", RegionHeader),
    ]

    def is_valid(self):
        """Check if this is a valid NTPI file"""
        return self.magic == b'NTPI'


class RegionBlockHeader(ctypes.Structure):
    """Header for region data blocks"""
    _fields_ = [
        ("this_header", RegionHeader),
        ("next_header", RegionHeader),
        ("real_size", ctypes.c_uint64),
    ]


class NTEncodeHeader(ctypes.Structure):
    """Header for encrypted/encoded blocks"""
    _fields_ = [
        ("magic", ctypes.c_char * 8),
        ("primary_type", ctypes.c_uint32),
        ("compress_subtype", ctypes.c_uint32),
        ("encrypt_subtype", ctypes.c_uint32),
        ("padding", ctypes.c_uint32),
        ("processed_size", ctypes.c_uint64),
        ("original_size", ctypes.c_uint64),
        ("key", ctypes.c_ubyte * 32),
        ("iv", ctypes.c_ubyte * 32),
        ("key_size", ctypes.c_uint32),
        ("iv_size", ctypes.c_uint32),
    ]


class NTDecompressHeader(ctypes.Structure):
    """Header for compressed data blocks"""
    _fields_ = [
        ("magic", ctypes.c_char * 8),
        ("primary_type", ctypes.c_uint32),
        ("decompress_subtype", ctypes.c_uint32),
        ("padding", ctypes.c_uint64),
        ("processed_size", ctypes.c_uint64),
        ("original_size", ctypes.c_uint64),
        ("padding2", ctypes.c_ubyte * 72),
    ]


# AES key dictionaries for different firmware versions
# Each version has its own set of region keys (key_1 to key_5) and IVs (iv_1 to iv_5)

# Version 1.3.0 keys (baseline)
AESDICT_V1_3_0 = {
    'key_1': '08ed9260dec3807aac3ec00e765186cf4b9c677601ba844f8ec3e8c2fe1e11cb',
    'iv_1': '0797205f6b02c0232cd2798795ba588d',
    'key_2': 'aa3308af05e8bd78945c46a99adecda3ec94f8c34dd3fcbd40488cf84e45c0bc',
    'iv_2': '7ad53c3bc931ae2cf0b87c27aa71e3e2',
    'key_3': '4d55ee7c82ea0b2fc2be1e71feafdd87bb34bd066c40e98d5cb19a3dc71cd817',
    'iv_3': 'ac3b2f2ef37d899adceade5beb72bf4a',
    'key_4': '0ed17e3f9a9fab2cff2cfcb5e4aa4f0c50e5c0ab70a45e27e50aa5a00cc27f4d',
    'iv_4': '6f24e12fecc93be5c8bc876a15d5f764',
    'key_5': 'a0a1a1c7de80ab9d9caa7536867f7b3ead74e37cf05bde47cfde33e9db13a88d',
    'iv_5': '10dd893e3a1ca6f8b54ca82ede28a45a',
}

# Version 1.2.1 keys - EXTRACTED VIA MEMORY DUMP + ENTROPY ANALYSIS (2026-02-05)
# Source: NothingFlashTool.exe memory dump during NTPI load
# Method: x32dbg memory dump -> entropy scan (25+ unique bytes/32) -> validation
# Validation: 35.5% readable content after decryption
# NOTE: These keys may be incorrect - memory dump extraction was heuristic-based
AESDICT_V1_2_1_MEMDUMP = {
    'key_1': '09eaf9230ddf42a07a65d973b92a81199664038536dc4758ecbb7b2e99f280ca',
    'iv_1': '89dc40458180edf423629b933252f6a7',
    'key_2': 'e738220d931eccbbb193e7b06d104e14ff1854775a5a9420b6cf71d8902123db',
    'iv_2': 'a377eba712a318cb7cad590cbc6ca42a',
    'key_3': '6ce104f42eb0c3294ae5ab95940541e53785fba1c23254851091a45b1c4e8c22',
    'iv_3': '0e7baa0f63abc2c1d8c725a669dc3ac2',
    'key_4': '7df8366de536b4e27c0f7283985089577d94826e04bb9f1c36333d79bd540005',
    'iv_4': '42b39a6cd859e8e2dc4d035ef68d606c',
    'key_5': '99f3d7186494053355c57ed3ab29af3569c4d64e14f85bb0baada2a3235b6727',
    'iv_5': '1f415cd01ad464e5fae6531268b1973d',
}

# Keys extracted via IDA Pro static analysis of NothingFlashTool.exe
# Source: sub_4A2F60 "ExtractRegionData" function in NothingFlashTool.exe
# Method: Traced AES-256-CBC decrypt calls → per-region key/IV from .rdata section
# Addresses: Key in .rdata at 0x7936C4-0x7937D0, IV at 0x7936E4-0x7937D0
# Cipher: AES-256-CBC (confirmed via EVP_CIPHER struct NID 427)
AESDICT_IDA_EXTRACT = {
    'key_1': 'd05fcf80565b968b5b60b800c08355f95a03c4c3e5d16d15476c88485b81bb36',
    'iv_1': '53fdc67453e5d2ab8eff5f0bdd0387f6',
    'key_2': '27e6ae479e2b1b59250371e81365204d2d19ec69bc7fb9df0c08049ab5406c97',
    'iv_2': '07fce1731c0bcb4c61a6d7dc54abbe65',
    'key_3': '740818a754554736498442e63cca25c8513dff980c2588ad8b18629259ce7fc9',
    'iv_3': '8a2cb5da308efbc5b8a47bcfedac0a2e',
    'key_4': 'afdf9fe1865d25c56cae7c201c459bc92f2b7cf19e33234e18069e2d872efb1f',
    'iv_4': 'f7958986d6efbf15e66d5c2ef9dbf94d',
    'key_5': '5629698b35f3e7268b8f907d095ee50a752b73a3dd62177ffc5c84e2ede38ace',
    'iv_5': 'ad4291eed4d11e2d78759104da0b9556',
}

# Example: Add more versions as needed
# AESDICT_V1_4_0 = {
#     'key_1': 'new_key_hex_string_here...',
#     'iv_1': 'new_iv_hex_string_here...',
#     ...
# }

# Version mapping: map version tuples to key dictionaries
VERSION_KEY_MAP = {
    (1, 2, 1): AESDICT_IDA_EXTRACT,  # Try IDA-extracted keys first
    (1, 3, 0): AESDICT_V1_3_0,
    # (1, 4, 0): AESDICT_V1_4_0,  # Add future versions here
}

# Default key dictionary (used when version is not recognized)
DEFAULT_AESDICT = AESDICT_V1_3_0

# Backward compatibility: keep AESDICT as default
AESDICT = DEFAULT_AESDICT


def validate_keys(keys_dict, version_str):
    """
    Validate that AES keys are not placeholder TODO values.
    
    Args:
        keys_dict: Dictionary containing AES keys and IVs
        version_str: Version string for error messages (e.g., "1.2.1")
    
    Returns:
        True if keys are valid, False if they contain TODO placeholders
    """
    if not keys_dict:
        return False
    
    # Check if any key or IV contains TODO placeholder
    for key_name, key_value in keys_dict.items():
        if 'TODO' in str(key_value).upper():
            return False
    
    return True


def get_aesdict_for_version(version_major, version_minor, version_patch):
    """
    Get the appropriate AES key dictionary for a specific firmware version.
    
    Args:
        version_major: Major version number (e.g., 1)
        version_minor: Minor version number (e.g., 3)
        version_patch: Patch version number (e.g., 0)
    
    Returns:
        Dictionary containing AES keys and IVs for the specified version.
        Returns None if version is not supported or keys are not available.
    
    Example:
        >>> keys = get_aesdict_for_version(1, 3, 0)
        >>> if keys:
        >>>     print(keys['key_1'])
    """
    version_tuple = (version_major, version_minor, version_patch)
    version_str = f"{version_major}.{version_minor}.{version_patch}"
    
    # Try to find exact version match
    if version_tuple in VERSION_KEY_MAP:
        keys_dict = VERSION_KEY_MAP[version_tuple]
        # Validate that keys are not TODO placeholders
        if not validate_keys(keys_dict, version_str):
            return None
        return keys_dict
    
    # Try to find partial match (major.minor)
    partial_version = (version_major, version_minor)
    for key, value in VERSION_KEY_MAP.items():
        if key[:2] == partial_version:
            # Validate that keys are not TODO placeholders
            if not validate_keys(value, version_str):
                return None
            return value
    
    # Return None if no match found (unsupported version)
    return None
