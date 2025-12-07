# QuickStart Guide

## Installation

1. Install Python 3.7 or higher
2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Basic Usage

### Extract NTPI Firmware File

```bash
python ntpi_main.py yourfile.ntpi
```

This will extract the firmware to a folder named `yourfile_extracted`.

### Specify Output Directory

```bash
python ntpi_main.py -f yourfile.ntpi -o /path/to/output
```

### Use Multiple Processes

```bash
python ntpi_main.py -f yourfile.ntpi -p 4
```

The `-p` option sets the number of parallel processes (default: 2).

### Keep Temporary Files

```bash
python ntpi_main.py -f yourfile.ntpi --keep-temp
```

Use `--keep-temp` to preserve temporary files for debugging.

## Example

```bash
python ntpi_main.py 12345.ntpi
```

Output will be saved to: `12345_extracted/`

## Drag and Drop (Windows)

On Windows, you can drag and drop an NTPI file directly onto `ntpi_main.exe` (after building with PyInstaller).
