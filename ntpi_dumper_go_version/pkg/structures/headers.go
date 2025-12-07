// Package structures defines all binary structures for NTPI file parsing
package structures

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// NTPIHeader represents the main NTPI file header
type NTPIHeader struct {
	Magic        [4]byte      // Should be "NTPI"
	Padding      uint32       // Padding bytes
	VersionMajor uint64       // Major version number
	VersionMinor uint64       // Minor version number
	VersionPatch uint64       // Patch version number
	FirstRegion  RegionHeader // First region header
}

// Size returns the size of NTPIHeader in bytes
func (h *NTPIHeader) Size() int {
	return 4 + 4 + 8 + 8 + 8 + 16 // magic + padding + 3*version + RegionHeader(16)
}

// IsValid checks if the NTPI header has the correct magic bytes
func (h *NTPIHeader) IsValid() bool {
	return bytes.Equal(h.Magic[:], []byte("NTPI"))
}

// Version returns a formatted version string
func (h *NTPIHeader) Version() string {
	return fmt.Sprintf("%d.%d.%d", h.VersionMajor, h.VersionMinor, h.VersionPatch)
}

// RegionHeader represents the header for each region
type RegionHeader struct {
	RegionType uint64 // Region type identifier (1-6)
	RegionSize uint64 // Size of region data in bytes
}

// Size returns the size of RegionHeader in bytes
func (h *RegionHeader) Size() int {
	return 16 // 8 + 8
}

// RegionBlockHeader represents the header for decrypted region data
type RegionBlockHeader struct {
	ThisHeader RegionHeader // Current region header
	NextHeader RegionHeader // Next region header (if any)
	RealSize   uint64       // Actual data size after header
}

// Size returns the size of RegionBlockHeader in bytes
func (h *RegionBlockHeader) Size() int {
	return 40 // 16 + 16 + 8
}

// NTEncodeHeader represents the header for encrypted/encoded blocks in Region6
type NTEncodeHeader struct {
	Magic            [8]byte  // Should be "NTENCODE"
	PrimaryType      uint32   // Primary type identifier
	CompressSubtype  uint32   // Compression subtype
	EncryptSubtype   uint32   // Encryption subtype
	Padding          uint32   // Padding
	ProcessedSize    uint64   // Size after processing (decompressed)
	OriginalSize     uint64   // Original size (encrypted/compressed)
	Key              [32]byte // AES key (usually not used, from KeyMap instead)
	IV               [32]byte // Initialization vector for AES-CBC
	KeySize          uint32   // Size of key in bytes
	IVSize           uint32   // Size of IV in bytes
}

// Size returns the size of NTEncodeHeader in bytes
func (h *NTEncodeHeader) Size() int {
	return 112 // 8 + 4*4 + 2*8 + 32 + 32 + 2*4
}

// IsValid checks if the NTEncode header has the correct magic bytes
func (h *NTEncodeHeader) IsValid() bool {
	return bytes.Equal(h.Magic[:], []byte("NTENCODE"))
}

// GetIV returns the IV as a byte slice (first 16 bytes)
func (h *NTEncodeHeader) GetIV() []byte {
	return h.IV[:16]
}

// NTDecompressHeader represents the header for compressed data blocks
type NTDecompressHeader struct {
	Magic              [8]byte  // Should be "NTENCODE"
	PrimaryType        uint32   // Primary type identifier
	DecompressSubtype  uint32   // Decompression subtype
	Padding            uint64   // Padding
	ProcessedSize      uint64   // Size after decompression
	OriginalSize       uint64   // Original compressed size
	Padding2           [72]byte // Additional padding
}

// Size returns the size of NTDecompressHeader in bytes
func (h *NTDecompressHeader) Size() int {
	return 112 // 8 + 4 + 4 + 8 + 8 + 8 + 72
}

// IsValid checks if the NTDecompress header has the correct magic bytes
func (h *NTDecompressHeader) IsValid() bool {
	return bytes.Equal(h.Magic[:], []byte("NTENCODE"))
}

// ParseNTPIHeader parses NTPI header from byte slice
func ParseNTPIHeader(data []byte) (*NTPIHeader, error) {
	if len(data) < 48 {
		return nil, fmt.Errorf("data too small for NTPI header: %d bytes", len(data))
	}

	header := &NTPIHeader{}
	buf := bytes.NewReader(data)

	if err := binary.Read(buf, binary.LittleEndian, header); err != nil {
		return nil, fmt.Errorf("failed to parse NTPI header: %w", err)
	}

	if !header.IsValid() {
		return nil, fmt.Errorf("invalid NTPI magic: %s", string(header.Magic[:]))
	}

	return header, nil
}

// ParseRegionHeader parses region header from byte slice
func ParseRegionHeader(data []byte) (*RegionHeader, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("data too small for region header: %d bytes", len(data))
	}

	header := &RegionHeader{}
	buf := bytes.NewReader(data)

	if err := binary.Read(buf, binary.LittleEndian, header); err != nil {
		return nil, fmt.Errorf("failed to parse region header: %w", err)
	}

	return header, nil
}

// ParseRegionBlockHeader parses region block header from byte slice
func ParseRegionBlockHeader(data []byte) (*RegionBlockHeader, error) {
	if len(data) < 40 {
		return nil, fmt.Errorf("data too small for region block header: %d bytes", len(data))
	}

	header := &RegionBlockHeader{}
	buf := bytes.NewReader(data)

	if err := binary.Read(buf, binary.LittleEndian, header); err != nil {
		return nil, fmt.Errorf("failed to parse region block header: %w", err)
	}

	return header, nil
}

// ParseNTEncodeHeader parses NTEncode header from byte slice
func ParseNTEncodeHeader(data []byte) (*NTEncodeHeader, error) {
	if len(data) < 112 {
		return nil, fmt.Errorf("data too small for NTEncode header: %d bytes", len(data))
	}

	header := &NTEncodeHeader{}
	buf := bytes.NewReader(data)

	if err := binary.Read(buf, binary.LittleEndian, header); err != nil {
		return nil, fmt.Errorf("failed to parse NTEncode header: %w", err)
	}

	if !header.IsValid() {
		return nil, fmt.Errorf("invalid NTEncode magic: %s", string(header.Magic[:]))
	}

	return header, nil
}

// ParseNTDecompressHeader parses NTDecompress header from byte slice
func ParseNTDecompressHeader(data []byte) (*NTDecompressHeader, error) {
	if len(data) < 112 {
		return nil, fmt.Errorf("data too small for NTDecompress header: %d bytes", len(data))
	}

	header := &NTDecompressHeader{}
	buf := bytes.NewReader(data)

	if err := binary.Read(buf, binary.LittleEndian, header); err != nil {
		return nil, fmt.Errorf("failed to parse NTDecompress header: %w", err)
	}

	if !header.IsValid() {
		return nil, fmt.Errorf("invalid NTDecompress magic: %s", string(header.Magic[:]))
	}

	return header, nil
}

// RegionName returns a human-readable name for a region type
func RegionName(regionType uint64) string {
	names := map[uint64]string{
		1: "Metadata",
		2: "Patch",
		3: "RawProgram",
		4: "KeyMap",
		5: "FileIndex",
		6: "Region6",
	}

	if name, ok := names[regionType]; ok {
		return name
	}
	return fmt.Sprintf("Unknown%d", regionType)
}
