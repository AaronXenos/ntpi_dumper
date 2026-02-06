"""
NTPI File Parser
Handles parsing of NTPI file structure and region extraction.

Supported header formats:
- V1.3.0: 48-byte header with region_type + region_size for first region
- V1.2.1: 40-byte header with only region_encrypted_size (no type field)
"""
import ctypes
import struct
import time
import xml.etree.ElementTree as ET
from colorama import Fore, Style

from .structures import (
    NTPIHeader, RegionHeader, RegionBlockHeader, get_aesdict_for_version
)
from .crypto import get_aes_key_iv_for_region, aes_cbc_decrypt


def extract_region_data(file_data, region_header, offset, output_dir, keys_dict=None, key_region_index=None):
    """
    Extract and decrypt a region from the NTPI file.
    
    Args:
        file_data: Complete NTPI file data in memory
        region_header: RegionHeader structure for this region
        offset: Byte offset where region data starts
        output_dir: Directory to save extracted files
        keys_dict: Dictionary of AES keys for decryption
        key_region_index: Override region index for key selection (for v1.2.1
                         where region_type isn't known before decryption)
    
    Returns:
        Tuple of (next_offset, next_region_header) or (-1, None) if no more regions
    """
    # Map region type IDs to human-readable names
    region_names = {
        1: "Metadata",
        2: "Patch",
        3: "RawProgram",
        4: "KeyMap",
        5: "FileIndex",
        6: "Region6"
    }

    # Determine which key to use: explicit index takes priority
    key_index = key_region_index if key_region_index is not None else region_header.region_type
    region_name = region_names.get(key_index, f"Unknown{key_index}")
    
    # Validate region boundaries
    if offset + region_header.region_size > len(file_data):
        print(f"{Fore.RED}Error: Region data out of bounds for {region_name}{Style.RESET_ALL}")
        exit(-1)
    
    # Extract region data
    region_data = file_data[offset:offset + region_header.region_size]
    
    # Region6 contains encrypted file blocks, save as-is for later processing
    if key_index == 6:
        output_file = output_dir / "region6block.bin"
        with open(output_file, 'wb') as f:
            f.write(region_data)
        return -1, None
    
    # Get decryption keys for this region
    key, iv = None, None
    if keys_dict:
        key, iv = get_aes_key_iv_for_region(key_index, keys_dict)
    
    # Decrypt the region data
    decrypted_data = aes_cbc_decrypt(region_data, key, iv)
    # Parse the block header from decrypted data
    if len(decrypted_data) < ctypes.sizeof(RegionBlockHeader):
        print(f"{Fore.RED}Error: Decrypted data for {region_name} is too small for a RegionBlockHeader{Style.RESET_ALL}")
        exit(-1)
    
    block_header = RegionBlockHeader.from_buffer_copy(decrypted_data[:ctypes.sizeof(RegionBlockHeader)])
    data_offset = ctypes.sizeof(RegionBlockHeader)
    
    # Extract actual data content
    if data_offset + block_header.real_size > len(decrypted_data):
        print(f"{Fore.RED}Error: Real data size for {region_name} exceeds decrypted data buffer{Style.RESET_ALL}")
        exit(-1)
    
    actual_data = decrypted_data[data_offset:data_offset + block_header.real_size]
    
    # Save to file (KeyMap is binary, others are XML)
    if key_index == 4:
        output_file = output_dir / f"{region_name}.bin"
    else:
        output_file = output_dir / f"{region_name}.xml"
    with open(output_file, 'wb') as f:
        f.write(actual_data)
    
    # Check if there's a next region to process
    if block_header.next_header.region_size > 0:
        next_offset = offset + region_header.region_size
        return next_offset, block_header.next_header
    else:
        return -1, None


def parse_ntpi_file(file_path, output_dir):
    """
    Parse NTPI file header and extract all regions (Stage 1).
    
    This function reads the NTPI file, validates its header, and extracts
    all regions (Metadata, Patch, RawProgram, KeyMap, FileIndex, Region6).
    
    Args:
        file_path: Path to the .ntpi file
        output_dir: Directory to save extracted region files
    
    Returns:
        True if successful, False otherwise
    """
    print(f"{Fore.CYAN}=== Stage 1: Parsing NTPI File... ==={Style.RESET_ALL}")
    stage1_start = time.time()
    
    # Validate file existence
    if not file_path.exists():
        print(f"{Fore.RED}Error: Input file not found: {file_path}{Style.RESET_ALL}")
        return False

    # Read entire file into memory
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    # Validate file size
    if len(file_data) < ctypes.sizeof(NTPIHeader):
        print(f"{Fore.RED}Error: File is too small to be a valid NTPI file.{Style.RESET_ALL}")
        return False
    
    # Parse NTPI header
    ntpi_header = NTPIHeader.from_buffer_copy(file_data[:ctypes.sizeof(NTPIHeader)])
    if not ntpi_header.is_valid():
        print(f"{Fore.RED}Error: Invalid NTPI file magic.{Style.RESET_ALL}")
        return False
    
    print(f"{Fore.GREEN}NTPI header parsed successfully. Version: {ntpi_header.version_major}.{ntpi_header.version_minor}.{ntpi_header.version_patch}{Style.RESET_ALL}")
    
    # Get AES keys for this specific version
    keys_dict = get_aesdict_for_version(
        ntpi_header.version_major,
        ntpi_header.version_minor,
        ntpi_header.version_patch
    )
    
    # Check if version is supported
    if keys_dict is None:
        print(f"{Fore.RED}Error: Unsupported firmware version {ntpi_header.version_major}.{ntpi_header.version_minor}.{ntpi_header.version_patch}{Style.RESET_ALL}")
        
        # Check if version is defined but keys are TODO placeholders
        from .structures import VERSION_KEY_MAP, validate_keys
        version_tuple = (ntpi_header.version_major, ntpi_header.version_minor, ntpi_header.version_patch)
        if version_tuple in VERSION_KEY_MAP:
            print(f"{Fore.YELLOW}This version is recognized but AES keys have not been extracted yet.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Action required: Extract AES keys from imageChecker.dll using IDA Pro{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Update the keys in utils/structures.py (AESDICT_V{ntpi_header.version_major}_{ntpi_header.version_minor}_{ntpi_header.version_patch}){Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}This version is not currently supported. Please add AES keys to utils/structures.py{Style.RESET_ALL}")
        
        print(f"{Fore.YELLOW}Supported versions with valid keys:{Style.RESET_ALL}")
        for ver in VERSION_KEY_MAP.keys():
            ver_str = f"{ver[0]}.{ver[1]}.{ver[2]}"
            if validate_keys(VERSION_KEY_MAP[ver], ver_str):
                print(f"{Fore.GREEN}  ✓ Version {ver_str}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}  ✗ Version {ver_str} (keys pending extraction){Style.RESET_ALL}")
        return False
    
    print(f"{Fore.CYAN}Using AES keys for version {ntpi_header.version_major}.{ntpi_header.version_minor}.{ntpi_header.version_patch}{Style.RESET_ALL}")

    # Determine header format based on version
    version_tuple = (ntpi_header.version_major, ntpi_header.version_minor, ntpi_header.version_patch)

    if version_tuple == (1, 2, 1):
        # V1.2.1 header: 40 bytes total
        #   [0:32]  common header (magic + padding + 3 version u64s)
        #   [32:40] first region encrypted blob size (u64)
        # Region data starts at offset 40. Region type is NOT in the header;
        # it's inside the encrypted RegionBlockHeader.
        first_enc_size = struct.unpack_from('<Q', file_data, 32)[0]
        current_offset = 40
        # Create synthetic RegionHeader: we don't know the type yet,
        # but we know size. We use key_region_index override below.
        current_region = RegionHeader()
        current_region.region_type = 0  # unknown from header
        current_region.region_size = first_enc_size
        region_index = 1  # regions always appear in order 1,2,3,4,5,6
        print(f"{Fore.CYAN}V1.2.1 header: region data starts at offset 40, first enc size = 0x{first_enc_size:x}{Style.RESET_ALL}")
    else:
        # V1.3.0+ header: 48 bytes with region_type + region_size at offset 32
        current_offset = ctypes.sizeof(NTPIHeader)
        current_region = ntpi_header.first_region_header
        region_index = current_region.region_type

    # Process all regions in sequence
    region_count = 0
    
    while current_region and current_region.region_size > 0:
        region_count += 1
        result = extract_region_data(
            file_data, current_region, current_offset, output_dir, keys_dict,
            key_region_index=region_index if version_tuple == (1, 2, 1) else None
        )
        if isinstance(result, tuple):
            next_offset, next_region = result
            if next_offset == -1:
                # Region 6 was saved; check if we need to process remaining
                if version_tuple == (1, 2, 1) and region_index < 6:
                    # Still have regions to go, but Region6 was hit
                    break
                break
            current_offset = next_offset
            current_region = next_region
            if version_tuple == (1, 2, 1):
                region_index += 1
            else:
                region_index = current_region.region_type if current_region else 0
        else:
            break
    
    stage1_elapsed = time.time() - stage1_start
    print(f"{Fore.GREEN}Stage 1 completed. Parsed {region_count} regions.{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Stage 1 Time: {stage1_elapsed:.2f}s{Style.RESET_ALL}")
    return True


def parse_fileindex_xml(xml_path):
    """
    Parse FileIndex.xml to get information about all files in the archive.
    
    Args:
        xml_path: Path to FileIndex.xml
    
    Returns:
        List of dictionaries containing file metadata (name, size, hash, etc.)
    """
    if not xml_path.exists():
        print(f"{Fore.RED}Error: FileIndex.xml not found at {xml_path}{Style.RESET_ALL}")
        return []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        files_info = []
        
        # Extract metadata for each file
        for file_elem in root.iter('file'):
            file_info = {
                'name': file_elem.get('Name', ''),
                'size': int(file_elem.get('OriginalLength', '0')),  # Decompressed size
                'length': int(file_elem.get('Length', '0')),  # Compressed size in Region6
                'hash': file_elem.get('FileSha256Hash', ''),  # SHA256 for verification
                'keyindex': int(file_elem.get('KeyIndex', '0')),  # Starting key index
                'offset': int(file_elem.get('Offset', '0'))  # Offset in Region6
            }
            files_info.append(file_info)
        
        print(f"{Fore.GREEN}Parsed {len(files_info)} file entries from FileIndex.xml.{Style.RESET_ALL}")
        return files_info
    except Exception as e:
        print(f"{Fore.RED}Error parsing FileIndex.xml: {e}{Style.RESET_ALL}")
        exit(-1)
