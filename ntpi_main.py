"""
NTPI Firmware Extraction Tool
Main entry point for extracting and decompressing firmware files from Nothing Phone NTPI archives.
"""
import argparse
import sys
import time
import shutil
import multiprocessing
from pathlib import Path
from colorama import init as colorama_init, Fore, Style

from version import __version__, __description__, __author__
from utils.parser import parse_ntpi_file
from utils.extractor import stage2_extract_files

colorama_init(autoreset=True)


def main():
    """
    Main entry point for NTPI firmware extraction tool.
    
    This tool extracts and decompresses firmware files from Nothing Phone NTPI archives.
    It features intelligent optimization for large files with multi-threaded segmentation.
    
    Usage:
        ntpi_main.exe <file.ntpi>
        ntpi_main.exe -f <file.ntpi> [-o output_dir] [-p processes]
    
    Options:
        -f, --file: Input NTPI file path
        -o, --output: Output directory (default: <filename>_extracted)
        -p, --processes: Number of worker processes (default: 2)
        --keep-temp: Keep temporary files for debugging
    """
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description=f'{__description__} v{__version__}',
        epilog=f'Author: {__author__}'
    )
    parser.add_argument('file_path', nargs='?', help='Path to NTPI file (can be dragged onto exe)')
    parser.add_argument('-f', '--file', dest='file_path_alt', help='Alternative way to specify file path')
    parser.add_argument('-o', '--output', default=None, help='Output directory')
    parser.add_argument('-p', '--processes', type=int, default=2, help='Number of parallel processes (default: 2)')
    parser.add_argument('--keep-temp', action='store_true', help='Keep temporary files after extraction')
    parser.add_argument('-v', '--version', action='version', version=f'%(prog)s {__version__}')
    args = parser.parse_args()

    # Get input file path from arguments
    file_path_str = args.file_path or args.file_path_alt
    
    # Show usage if no file specified
    if not file_path_str:
        print(f"{Fore.YELLOW}Usage: Drag and drop an NTPI file onto this exe, or use:{Style.RESET_ALL}")
        print(f"  ntpi_main.exe <file.ntpi>")
        print(f"  ntpi_main.exe -f <file.ntpi> [-o output_dir] [-p processes]")
        print(f"\n{Fore.GREEN}Features: Optimized for large files (>=500MB) with multi-threaded segmentation{Style.RESET_ALL}")
        print(f"\nPress Enter to exit...")
        input()
        sys.exit(1)
    
    file_path = Path(file_path_str)

    # Determine output directory
    if args.output:
        final_output_dir = Path(args.output)
    else:
        final_output_dir = file_path.parent / f"{file_path.stem}_extracted"

    # Create temporary directory for stage 1 output
    temp_dir = Path('./.temp')
    if temp_dir.exists():
        shutil.rmtree(temp_dir)
    temp_dir.mkdir(parents=True)

    # Start timing
    total_start = time.time()
    
    try:
        # Stage 1: Parse NTPI file and extract regions
        success = parse_ntpi_file(file_path, temp_dir)
        if not success:
            print(f"\n{Fore.RED}Extraction failed. Press Enter to exit...{Style.RESET_ALL}")
            input()
            sys.exit(1)

        # Stage 2: Extract and decompress all files from Region6
        stage2_success = stage2_extract_files(temp_dir, final_output_dir, process_count=args.processes)
        if not stage2_success:
            print(f"\n{Fore.RED}Extraction failed. Press Enter to exit...{Style.RESET_ALL}")
            input()
            sys.exit(1)

        # Move configuration XMLs to output directory
        print(f"{Fore.CYAN}Moving configuration files...{Style.RESET_ALL}")
        for filename in ["Patch.xml", "RawProgram.xml"]:
            src_path = temp_dir / filename
            dest_path = final_output_dir / filename
            if src_path.exists():
                try:
                    shutil.move(str(src_path), str(dest_path))
                except Exception as e:
                    print(f"{Fore.RED}Failed to move {filename}: {e}{Style.RESET_ALL}")
        
        # Handle temporary files based on --keep-temp flag
        if args.keep_temp:
            print(f"{Fore.YELLOW}Temporary files kept in: {temp_dir.absolute()}{Style.RESET_ALL}")
        else:
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
        
        # Print final summary
        total_elapsed = time.time() - total_start
        print(f"\n{Fore.GREEN}All files extracted successfully!{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Output directory: {final_output_dir}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Total Time: {total_elapsed:.2f}s ({total_elapsed/60:.2f} min){Style.RESET_ALL}")
        print(f"\nPress Enter to exit...")
        input()

    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        print(f"\n{Fore.YELLOW}Process interrupted by user. Cleaning up...{Style.RESET_ALL}")
        if not args.keep_temp and temp_dir.exists():
            try:
                shutil.rmtree(temp_dir)
            except:
                pass
        print(f"\nPress Enter to exit...")
        input()
        sys.exit(1)
    except Exception as e:
        # Handle unexpected errors
        print(f"\n{Fore.RED}Unexpected error: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        if not args.keep_temp and temp_dir.exists():
            try:
                shutil.rmtree(temp_dir)
            except:
                pass
        print(f"\nPress Enter to exit...")
        input()
        sys.exit(1)
    finally:
        # Final cleanup
        if not args.keep_temp and temp_dir.exists():
            try:
                shutil.rmtree(temp_dir)
            except:
                pass


if __name__ == "__main__":
    # Required for Windows exe packaging with multiprocessing
    multiprocessing.freeze_support()
    main()
