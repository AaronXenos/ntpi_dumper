# GitHub Actions Workflows

This directory contains GitHub Actions workflows for automated building and releasing of NTPI Dumper.

## Workflows

### 1. Build and Release (`build-release.yml`)

**Trigger:** Automatically runs when a version tag is pushed (e.g., `v0.1.0`)

**Purpose:** Builds executables for both x86 and x86_64 architectures and creates a GitHub Release with the binaries and SHA256 checksums.

**Steps:**
1. Builds `ntpi_dumper_x86.exe` (32-bit)
2. Builds `ntpi_dumper_x86_64.exe` (64-bit)
3. Calculates SHA256 checksums for both files
4. Creates a GitHub Release with:
   - Both executable files
   - SHA256 checksum files
   - Detailed release notes
   - Download links and verification instructions

**Usage:**
```bash
# Create and push a version tag
git tag v0.1.0
git push origin v0.1.0

# The workflow will automatically run and create a release
```

### 2. Manual Build (`manual-build.yml`)

**Trigger:** Manual trigger from GitHub Actions tab

**Purpose:** Build and test executables without creating a release. Useful for testing changes before creating a release.

**Steps:**
1. Builds both x86 and x86_64 executables
2. Tests executables (runs `--version` and `--help`)
3. Uploads artifacts for download
4. Generates a build summary with file sizes and SHA256 checksums

**Usage:**
1. Go to the "Actions" tab in your GitHub repository
2. Select "Manual Build" workflow
3. Click "Run workflow"
4. Download artifacts from the workflow run page

## Architecture Support

| Architecture | Python Bits | Target Systems |
|--------------|-------------|----------------|
| x86 | 32-bit | Windows 7/8/10/11 (32-bit and 64-bit systems) |
| x86_64 | 64-bit | Windows 7/8/10/11 (64-bit systems only) |

**Note:** x86 (32-bit) executables can run on both 32-bit and 64-bit Windows, but x86_64 (64-bit) executables only run on 64-bit Windows.

## File Naming Convention

- `ntpi_dumper_x86.exe` - 32-bit executable
- `ntpi_dumper_x86_64.exe` - 64-bit executable
- `ntpi_dumper_x86.exe.sha256` - SHA256 checksum for 32-bit
- `ntpi_dumper_x86_64.exe.sha256` - SHA256 checksum for 64-bit

## SHA256 Verification

After downloading, users can verify the integrity of the executables:

**Windows PowerShell:**
```powershell
(Get-FileHash -Algorithm SHA256 ntpi_dumper_x86_64.exe).Hash
```

**Linux/macOS:**
```bash
sha256sum ntpi_dumper_x86_64.exe
```

Compare the output with the checksum provided in the release notes or `.sha256` file.

## Release Process

### Automated Release (Recommended)

1. Update version in `version.py`:
   ```python
   __version__ = '0.2.0'
   VERSION_TUPLE = (0, 2, 0, 0)
   ```

2. Update `version_info.txt` with new version numbers

3. Update `CHANGELOG.md` with changes

4. Commit changes:
   ```bash
   git add version.py version_info.txt CHANGELOG.md
   git commit -m "Bump version to 0.2.0"
   git push
   ```

5. Create and push tag:
   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

6. Wait for GitHub Actions to complete (builds take ~5-10 minutes)

7. Check the "Releases" page for your new release!

### Manual Testing Before Release

1. Run the "Manual Build" workflow from GitHub Actions
2. Download and test the artifacts
3. If everything works, proceed with creating a tag for release

## Requirements

The workflows use:
- `actions/checkout@v4` - Checkout code
- `actions/setup-python@v5` - Setup Python with architecture selection
- `actions/upload-artifact@v4` - Upload build artifacts
- `actions/download-artifact@v4` - Download artifacts
- `softprops/action-gh-release@v1` - Create GitHub releases

## Permissions

The workflows require `contents: write` permission to create releases and upload assets.

## Troubleshooting

### Build fails
- Check Python version compatibility (currently using Python 3.11)
- Verify all dependencies are in `requirements.txt`
- Check PyInstaller spec file syntax

### Release not created
- Ensure tag follows `v*.*.*` format
- Check repository permissions
- Verify `GITHUB_TOKEN` has write access

### SHA256 checksum mismatch
- Re-download the file (may be corrupted)
- Ensure you're comparing with the correct architecture's checksum
- Check if file was modified after download

## Local Testing

To test the build process locally:

```powershell
# Install dependencies
pip install -r requirements.txt
pip install pyinstaller

# Build
pyinstaller ntpi_main.spec

# Calculate SHA256
(Get-FileHash -Path "dist\ntpi_dumper.exe" -Algorithm SHA256).Hash

# Test
.\dist\ntpi_dumper.exe --version
.\dist\ntpi_dumper.exe --help
```

## Notes

- Build artifacts are retained for 30 days (manual builds) or 5 days (release builds)
- Each build takes approximately 3-5 minutes per architecture
- Total workflow time: ~10-15 minutes for both architectures plus release creation
- Release notes are automatically generated from version information and checksums
