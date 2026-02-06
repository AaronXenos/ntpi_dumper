"""
File Extraction and Decompression
Handles extraction of files from Region6 with multi-threaded optimization.
"""
import os
import sys
import ctypes
import time
import hashlib
import lzma
import mmap
import multiprocessing
from pathlib import Path
from tqdm import tqdm
from colorama import Fore, Style
from concurrent.futures import ThreadPoolExecutor

from .structures import NTEncodeHeader, NTDecompressHeader
from .crypto import extract_key_from_keymap, decrypt_NTEncode_data


# ===== Global variables for multiprocessing workers =====
G_REGION6_DATA = None  # Memory-mapped region6 data (or bytes fallback)
G_REGION6_FILE = None  # File handle kept alive while mmap is active
G_KEYMAP_DATA = None   # Keymap data for AES decryption keys (4KB)
G_PBAR_LOCK = None     # Lock for synchronized console output
G_COMPLETED_COUNTER = None  # Atomic counter for tracking completed files


def init_worker(region6_path, keymap_path, pbar_lock, completed_counter):
    """
    Initialize global variables in each worker process.
    
    Uses memory-mapped files for Region6 access to avoid loading
    the entire file (3+ GB) into each worker's memory. The OS
    manages paging and deduplicates physical pages across workers.
    
    Args:
        region6_path: Path to region6block.bin file
        keymap_path: Path to KeyMap.bin file
        pbar_lock: Multiprocessing lock for synchronized output
        completed_counter: Shared counter for progress tracking
    """
    global G_REGION6_DATA, G_REGION6_FILE, G_KEYMAP_DATA, G_PBAR_LOCK, G_COMPLETED_COUNTER
    
    # Memory-map the region6 file (read-only)
    # Each worker gets its own mmap view, but the OS shares physical pages
    G_REGION6_FILE = open(region6_path, 'rb')
    G_REGION6_DATA = mmap.mmap(G_REGION6_FILE.fileno(), 0, access=mmap.ACCESS_READ)
    
    # Load keymap into memory (only ~4KB, negligible)
    with open(keymap_path, 'rb') as f:
        G_KEYMAP_DATA = f.read()
    
    G_PBAR_LOCK = pbar_lock
    G_COMPLETED_COUNTER = completed_counter
    
    # Validate that data was successfully initialized
    if G_REGION6_DATA is None or G_KEYMAP_DATA is None:
        print(f"{Fore.RED}Critical error in worker: global data is not initialized.{Style.RESET_ALL}")
        sys.exit(1)


def decompress_lzma2_data(decrypted_data):
    """
    Decompress LZMA2-compressed data from a decrypted NTEncode block.
    
    Args:
        decrypted_data: Decrypted data starting with NTDecompressHeader
    
    Returns:
        Decompressed data as bytes
    """
    # Validate header size
    if len(decrypted_data) < ctypes.sizeof(NTDecompressHeader):
        print(f"{Fore.RED}Error: Data is too small for NTDecompressHeader{Style.RESET_ALL}")
        exit(-1)
    
    # Validate magic bytes
    if not decrypted_data.startswith(b'NTENCODE'):
        print(f"{Fore.RED}Error: Invalid NTDecompressHeader magic{Style.RESET_ALL}")
        exit(-1)
    
    # Parse decompression header
    nt_decompress_header = NTDecompressHeader.from_buffer_copy(decrypted_data[:ctypes.sizeof(NTDecompressHeader)])
    
    # Compressed data starts at offset 0x70 (112 bytes)
    data_offset = 0x70
    if data_offset >= len(decrypted_data):
        print(f"{Fore.RED}Error: Data offset exceeds data range in lzma block{Style.RESET_ALL}")
        exit(-1)
    
    compressed_data = decrypted_data[data_offset:]
    
    try:
        # Decompress using LZMA2 algorithm (RAW format)
        decompressed_data = lzma.decompress(compressed_data, format=lzma.FORMAT_RAW,
                                            filters=[{"id": lzma.FILTER_LZMA2}])
        return decompressed_data
    except lzma.LZMAError as e:
        print(f"{Fore.RED}LZMA2 decompression failed: {e}{Style.RESET_ALL}")
        raise
    except Exception as e:
        print(f"{Fore.RED}Unknown error during decompression: {e}{Style.RESET_ALL}")
        raise


def split_file_into_segments(fileinfo, num_segments=4):
    """
    Split a large file into segments for parallel processing.
    
    Each segment contains complete NTEncode blocks. This function scans
    all block boundaries and divides them evenly by decompressed size.
    
    Args:
        fileinfo: File metadata dictionary
        num_segments: Number of segments to create
    
    Returns:
        List of segment descriptors: [{start_offset, end_offset, start_block_index, num_blocks}, ...]
    """
    global G_REGION6_DATA
    
    offset_start = fileinfo['offset']
    offset_end = offset_start + fileinfo['length']
    
    # Step 1: Scan all block boundaries in this file's region
    block_boundaries = []  # [(offset, block_index, accumulated_size), ...]
    current_offset = offset_start
    block_index = 0
    accumulated_size = 0
    
    while current_offset < offset_end:
        # Validate header boundaries
        if current_offset + ctypes.sizeof(NTEncodeHeader) > len(G_REGION6_DATA):
            break
        
        # Parse block header to get size information
        nt_header = NTEncodeHeader.from_buffer_copy(
            G_REGION6_DATA[current_offset:current_offset + ctypes.sizeof(NTEncodeHeader)]
        )
        
        if nt_header.magic != b'NTENCODE':
            break
        
        # Record this block's starting position and metadata
        block_boundaries.append((current_offset, block_index, accumulated_size))
        
        # Move to next block
        encrypted_size = nt_header.original_size
        block_size = ctypes.sizeof(NTEncodeHeader) + encrypted_size
        current_offset += block_size
        block_index += 1
        
        # Accumulate decompressed size for balanced segmentation
        accumulated_size += nt_header.processed_size
    
    total_blocks = len(block_boundaries)
    if total_blocks == 0:
        raise ValueError(f"No valid blocks found for file {fileinfo['name']}")
    
    # Step 2: Divide blocks into segments
    # Goal: Balance each segment's decompressed data size
    target_size_per_segment = accumulated_size / num_segments
    
    segments = []
    segment_start_idx = 0
    current_segment_size = 0
    
    for i in range(total_blocks):
        current_segment_size = block_boundaries[i][2] - block_boundaries[segment_start_idx][2]
        
        # Decide if current segment should end
        should_end_segment = False
        if len(segments) < num_segments - 1:  # Not the last segment yet
            if current_segment_size >= target_size_per_segment:
                should_end_segment = True
        
        if should_end_segment or i == total_blocks - 1:
            # Finalize current segment
            start_offset = block_boundaries[segment_start_idx][0]
            start_block_idx = block_boundaries[segment_start_idx][1]
            
            if i == total_blocks - 1:
                # Last segment: go to file end
                end_offset = offset_end
                num_blocks = total_blocks - segment_start_idx
            else:
                # Middle segment: go to next block start
                end_offset = block_boundaries[i + 1][0] if i + 1 < total_blocks else offset_end
                num_blocks = i - segment_start_idx + 1
            
            segments.append({
                'start_offset': start_offset,
                'end_offset': end_offset,
                'start_block_index': start_block_idx,
                'num_blocks': num_blocks
            })
            
            # Start next segment
            segment_start_idx = i + 1
            current_segment_size = 0
    
    return segments


def process_segment(fileinfo, segment_info, segment_id):
    """
    Process a single file segment (worker function for parallel processing).
    
    This function is called by ThreadPoolExecutor to process one segment
    of a large file. It decrypts and decompresses all blocks in the segment.
    
    Args:
        fileinfo: File metadata dictionary
        segment_info: Segment descriptor {start_offset, end_offset, start_block_index, num_blocks}
        segment_id: Segment identifier (for debugging)
    
    Returns:
        Decompressed data for this segment
    """
    global G_REGION6_DATA, G_KEYMAP_DATA
    
    start_offset = segment_info['start_offset']
    end_offset = segment_info['end_offset']
    start_block_index = segment_info['start_block_index']
    
    segment_data = []
    current_offset = start_offset
    block_count = 0
    
    while current_offset < end_offset:
        # Calculate key index for current block
        # Key index = file's base key index + block offset within file
        current_key_index = fileinfo['keyindex'] + start_block_index + block_count
        key = extract_key_from_keymap(G_KEYMAP_DATA, current_key_index)
        
        # Decrypt current block
        next_offset, decrypted_data = decrypt_NTEncode_data(G_REGION6_DATA, current_offset, key)
        
        # Decompress decrypted data
        decompressed_data = decompress_lzma2_data(decrypted_data)
        segment_data.append(decompressed_data)
        
        current_offset = next_offset
        block_count += 1
    
    # Concatenate all decompressed blocks in this segment
    return b''.join(segment_data)


def calculate_optimal_segments(file_size):
    """
    Calculate optimal number of segments based on file size and CPU cores.
    
    This function implements an intelligent segmentation strategy:
    - Small files (<500MB): No segmentation (sequential processing faster)
    - Medium files (500MB-1GB): 2 segments
    - Large files (1GB-2GB): 4 segments
    - Very large files (2GB-4GB): 6 segments
    - Huge files (>4GB): 8 segments
    
    Segment count is capped at available CPU cores to avoid over-threading.
    
    Args:
        file_size: File size in bytes
    
    Returns:
        Optimal number of segments (1-8)
    """
    cpu_count = os.cpu_count() or 4
    
    # Adaptive segmentation strategy based on file size
    if file_size < 500 * 1024 * 1024:  # < 500MB
        return 1  # Sequential processing, no overhead
    elif file_size < 1024 * 1024 * 1024:  # 500MB - 1GB
        return min(2, cpu_count)
    elif file_size < 2 * 1024 * 1024 * 1024:  # 1GB - 2GB
        return min(4, cpu_count)
    elif file_size < 4 * 1024 * 1024 * 1024:  # 2GB - 4GB
        return min(6, cpu_count)
    else:  # > 4GB
        return min(8, cpu_count)


def process_large_file_parallel(fileinfo, files_output_dir, position):
    """
    Multi-threaded parallel processing for large files (>= 500MB).
    
    This function splits large files into segments and processes them
    in parallel using ThreadPoolExecutor, providing 3-4x speedup.
    
    Args:
        fileinfo: File metadata dictionary
        files_output_dir: Directory to save extracted files
        position: Progress bar position (for multi-process coordination)
    
    Returns:
        Tuple of (filename, success, message)
    """
    global G_REGION6_DATA, G_COMPLETED_COUNTER, G_PBAR_LOCK
    
    filename = fileinfo['name']
    expected_size = fileinfo['size']
    expected_hash = fileinfo['hash'].lower()
    output_file = files_output_dir / filename
    
    try:
        # Calculate optimal segment count based on file size and CPU
        num_segments = calculate_optimal_segments(expected_size)
        segment_start_time = time.time()
        
        # Print processing info (synchronized to avoid console corruption)
        with G_PBAR_LOCK:
            print(f"\n{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Large File Processing: {filename}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}   File Size: {expected_size/(1024**2):.2f} MB{Style.RESET_ALL}")
            print(f"{Fore.CYAN}   CPU Cores: {os.cpu_count()}, Optimal Segments: {num_segments}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}   Analyzing block structure...{Style.RESET_ALL}")
        
        # Split file into segments at block boundaries
        segments = split_file_into_segments(fileinfo, num_segments)
        
        with G_PBAR_LOCK:
            print(f"{Fore.GREEN}   Split into {len(segments)} segments, ~{expected_size/(1024**2)/len(segments):.2f} MB each{Style.RESET_ALL}")
            for i, seg in enumerate(segments):
                print(f"{Fore.CYAN}     Segment {i+1}: {seg['num_blocks']} blocks{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}   Starting {num_segments}-thread parallel processing...{Style.RESET_ALL}")
        
        # Process segments in parallel using thread pool
        with ThreadPoolExecutor(max_workers=num_segments) as executor:
            futures = []
            for seg_id, segment_info in enumerate(segments):
                # Submit each segment to thread pool
                future = executor.submit(process_segment, fileinfo, segment_info, seg_id)
                futures.append(future)
            
            # Collect results in order (important for correct file reassembly)
            segment_results = []
            for seg_id, future in enumerate(futures):
                with G_PBAR_LOCK:
                    print(f"{Fore.CYAN}   Waiting for segment {seg_id+1}...{Style.RESET_ALL}")
                seg_data = future.result()
                segment_results.append(seg_data)
                with G_PBAR_LOCK:
                    print(f"{Fore.GREEN}   Segment {seg_id+1} completed ({len(seg_data)/(1024**2):.2f} MB){Style.RESET_ALL}")
        
        # Merge all segments into final file
        with G_PBAR_LOCK:
            print(f"{Fore.CYAN}   Merging all segments...{Style.RESET_ALL}")
        
        final_data = b''.join(segment_results)
        actual_size = len(final_data)
        
        # Verify decompressed size matches expected
        if actual_size != expected_size:
            with G_PBAR_LOCK:
                print(f"{Fore.YELLOW}   Size mismatch: Expected {expected_size/(1024**2):.2f} MB, "
                      f"Got {actual_size/(1024**2):.2f} MB{Style.RESET_ALL}")
        
        # Verify SHA256 hash for data integrity
        with G_PBAR_LOCK:
            print(f"{Fore.CYAN}   Verifying SHA256...{Style.RESET_ALL}")
        
        actual_hash = hashlib.sha256(final_data).hexdigest().lower()
        if actual_hash != expected_hash:
            with G_PBAR_LOCK:
                print(f"{Fore.RED}   Hash verification failed!{Style.RESET_ALL}")
            return (filename, False, f"Hash mismatch")
        
        # Write final data to output file
        with G_PBAR_LOCK:
            print(f"{Fore.CYAN}   Writing to disk...{Style.RESET_ALL}")
        
        with open(output_file, 'wb') as f:
            f.write(final_data)
        
        # Calculate and display performance metrics
        process_time = time.time() - segment_start_time
        speed = expected_size / (1024**2) / process_time  # MB/s
        
        with G_PBAR_LOCK:
            print(f"{Fore.GREEN}   Completed! Time: {process_time:.2f}s, Speed: {speed:.2f} MB/s{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}\n")
        
        # Update global completion counter for progress bar
        with G_COMPLETED_COUNTER.get_lock():
            G_COMPLETED_COUNTER.value += 1
        
        return (filename, True, str(output_file))
        
    except Exception as e:
        return (filename, False, f"Processing failed: {e}")


def process_file_task(fileinfo, files_output_dir, position):
    """
    Process a single file (dispatcher function).
    
    Routes to appropriate processing method based on file size:
    - Small files (<500MB): Sequential processing
    - Large files (>=500MB): Multi-threaded segmented processing
    
    Args:
        fileinfo: File metadata dictionary
        files_output_dir: Directory to save extracted files
        position: Progress bar position for tqdm
    
    Returns:
        Tuple of (filename, success, message)
    """
    global G_REGION6_DATA, G_COMPLETED_COUNTER, G_PBAR_LOCK, G_KEYMAP_DATA
    
    LARGE_FILE_THRESHOLD = 500 * 1024 * 1024  # 500MB
    
    # Route large files to parallel processing
    if fileinfo['size'] >= LARGE_FILE_THRESHOLD:
        return process_large_file_parallel(fileinfo, files_output_dir, position)
    
    # Small files: Sequential processing (original logic)
    offset_start = fileinfo['offset']
    offset_end = offset_start + fileinfo['length']
    filename = fileinfo['name']
    expected_size = fileinfo['size']
    expected_hash = fileinfo['hash'].lower()
    output_file = files_output_dir / filename

    try:
        final_data_list = []
        process_offset = offset_start
        index = 0
        
        # Create progress bar for this file
        with tqdm(total=expected_size, desc=f"{filename[:40]:<40}", unit='B', 
                 unit_scale=True, position=position + 1, leave=False, ncols=100) as pbar:
            while True:
                # Get key for current block
                key = extract_key_from_keymap(G_KEYMAP_DATA, fileinfo['keyindex'] + index)
                index += 1
                
                # Decrypt and decompress current block
                process_offset, decrypted_data = decrypt_NTEncode_data(G_REGION6_DATA, process_offset, key)
                decompress_data = decompress_lzma2_data(decrypted_data)
                final_data_list.append(decompress_data)
                
                # Update progress bar
                pbar.update(len(decompress_data))
                
                # Check if we've processed all blocks for this file
                if process_offset >= offset_end:
                    break

        # Combine all decompressed blocks
        final_data = b''.join(final_data_list)
        actual_size = len(final_data)

        # Verify size
        if actual_size != expected_size:
            with G_PBAR_LOCK:
                print(f"{Fore.YELLOW}Warning: {filename} size mismatch. Expected {expected_size}, Got {actual_size}{Style.RESET_ALL}")

        # Verify hash for data integrity
        actual_hash = hashlib.sha256(final_data).hexdigest().lower()
        if actual_hash != expected_hash:
            return (filename, False, f"Hash mismatch")

        # Write to output file
        with open(output_file, 'wb') as f:
            f.write(final_data)

        # Update completion counter
        with G_COMPLETED_COUNTER.get_lock():
            G_COMPLETED_COUNTER.value += 1

        return (filename, True, str(output_file))

    except Exception as e:
        return (filename, False, f"Processing failed: {e}")


def stage2_extract_files(temp_dir, final_output_dir, all_files=True, process_count=None):
    """
    Extract and decompress all files from Region6 (Stage 2).
    
    This function coordinates parallel extraction of files using multiprocessing.
    Large files (>=500MB) are further parallelized with multi-threaded segmentation.
    
    Args:
        temp_dir: Directory containing extracted region files from Stage 1
        final_output_dir: Directory to save final extracted files
        all_files: If False, only process first file (for testing)
        process_count: Number of worker processes (default: CPU count)
    
    Returns:
        True if all files extracted successfully, False otherwise
    """
    from .parser import parse_fileindex_xml
    
    print(f"\n{Fore.CYAN}=== Stage 2: Extracting Files (Optimized)... ==={Style.RESET_ALL}")
    stage2_start = time.time()
    
    # Verify required input files exist
    fileindex_path = temp_dir / "FileIndex.xml"
    keymap_path = temp_dir / "KeyMap.bin"
    region6_path = temp_dir / "region6block.bin"
    for path in [fileindex_path, keymap_path, region6_path]:
        if not path.exists():
            print(f"{Fore.RED}Error: Required file for stage 2 not found: {path}{Style.RESET_ALL}")
            exit(-1)

    # Create output directory
    files_output_dir = final_output_dir
    try:
        files_output_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"{Fore.RED}Failed to create output directory: {e}{Style.RESET_ALL}")
        files_output_dir = final_output_dir
    
    # Parse FileIndex.xml to get list of all files
    files_info = parse_fileindex_xml(fileindex_path)
    if not files_info:
        print(f"{Fore.RED}Error: No file information found in FileIndex.xml{Style.RESET_ALL}")
        exit(-1)
    
    # Test mode: process only first file
    if not all_files:
        print(f"{Fore.YELLOW}--- Running in test mode: processing only the first file. ---{Style.RESET_ALL}")
        files_info = files_info[:1]

    # Sort by file size: small files first, large files last
    # This provides better UX (small files complete quickly, large files run in parallel at end)
    LARGE_FILE_THRESHOLD = 500 * 1024 * 1024  # 500MB
    small_files = [f for f in files_info if f['size'] < LARGE_FILE_THRESHOLD]
    large_files = [f for f in files_info if f['size'] >= LARGE_FILE_THRESHOLD]
    
    # Reorder: small files first, large files last
    files_info = small_files + large_files
    
    if large_files:
        print(f"{Fore.GREEN}Detected {len(large_files)} large file(s) (>=500MB), will use multi-threaded acceleration{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Strategy: Process {len(small_files)} small files first, then large files{Style.RESET_ALL}")
    
    # Get region6 file size for progress info (without loading into memory)
    region6_size = region6_path.stat().st_size
    print(f"Region6 size: {region6_size / (1024**3):.2f} GB (using memory-mapped I/O)")

    # Determine number of worker processes
    PROCESS_COUNT = process_count if process_count else os.cpu_count() or 8
    
    # Create shared resources for multiprocessing
    manager = multiprocessing.Manager()
    pbar_lock = manager.Lock()  # For synchronized console output
    completed_counter = multiprocessing.Value('i', 0)  # Atomic counter
    
    # Create total progress bar (always at bottom, below worker progress bars)
    total_pbar = tqdm(
        total=len(files_info), 
        desc="Total Progress", 
        unit="file", 
        position=PROCESS_COUNT + 1,  # Position below all worker progress bars
        leave=True, 
        ncols=100
    )

    # Create task list: each task is (fileinfo, output_dir, progress_bar_position)
    tasks = [
        (fileinfo, files_output_dir, i % PROCESS_COUNT)
        for i, fileinfo in enumerate(files_info)
    ]

    # Create multiprocessing pool and process all files
    # Workers use mmap for region6 access (no pickle/copy of multi-GB data)
    with multiprocessing.Pool(
            processes=PROCESS_COUNT,
            initializer=init_worker,
            initargs=(str(region6_path), str(keymap_path), pbar_lock, completed_counter)
    ) as pool:
        
        try:
            # Start async processing of all tasks
            async_result = pool.starmap_async(process_file_task, tasks)
            
            # Monitor progress and update total progress bar
            while not async_result.ready():
                with completed_counter.get_lock():
                    current = completed_counter.value
                if total_pbar.n != current:
                    total_pbar.n = current
                    total_pbar.refresh()
                time.sleep(0.1)  # Update every 100ms for smooth progress
            
            # Get results after all tasks complete
            pool_results = async_result.get()
            
        except KeyboardInterrupt:
            # Handle Ctrl+C gracefully
            print(f"\n{Fore.YELLOW}Interrupted by user. Terminating workers...{Style.RESET_ALL}")
            total_pbar.close()
            pool.terminate()
            pool.join()
            sys.exit(1)
    
    # Final progress bar update
    total_pbar.n = completed_counter.value
    total_pbar.refresh()
    total_pbar.close()

    # Count successes and failures
    success_count = 0
    fail_count = 0
    for (name, success, message) in pool_results:
        if success:
            success_count += 1
        else:
            fail_count += 1
            tqdm.write(f"{Fore.RED}Failed to extract {name}: {message}{Style.RESET_ALL}")

    # Print stage 2 summary
    stage2_elapsed = time.time() - stage2_start
    print(f"\n{Fore.GREEN}Stage 2 Complete. Success: {success_count}, Failed: {fail_count}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Stage 2 Time: {stage2_elapsed:.2f}s ({stage2_elapsed/60:.2f} min){Style.RESET_ALL}")
    if success_count > 0:
        avg_time = stage2_elapsed / success_count
        print(f"{Fore.CYAN}Average time per file: {avg_time:.2f}s{Style.RESET_ALL}")
    
    return fail_count == 0
