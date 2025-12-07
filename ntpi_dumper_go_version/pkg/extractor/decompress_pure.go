// Package extractor - Pure Go LZMA2 decompression (fallback)
//go:build !cgo
// +build !cgo

package extractor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/YunWaiHe/ntpi-dumper-go/pkg/structures"
	"github.com/ulikunitz/xz/lzma"
)

// decompressLZMA2 decompresses LZMA2-compressed data (Pure Go implementation)
func decompressLZMA2(decryptedData []byte) ([]byte, error) {
	// Validate minimum size for header
	if len(decryptedData) < 112 {
		return nil, fmt.Errorf("data too small for NTDecompress header: %d bytes", len(decryptedData))
	}

	// Validate magic bytes
	if !bytes.HasPrefix(decryptedData, []byte("NTENCODE")) {
		return nil, fmt.Errorf("invalid NTDecompress header magic")
	}

	// Parse decompression header (for validation)
	_, err := structures.ParseNTDecompressHeader(decryptedData[:112])
	if err != nil {
		return nil, fmt.Errorf("failed to parse NTDecompress header: %w", err)
	}

	// Compressed data starts at offset 0x70 (112 bytes)
	dataOffset := 0x70
	if dataOffset >= len(decryptedData) {
		return nil, fmt.Errorf("data offset exceeds data range")
	}

	compressedData := decryptedData[dataOffset:]

	// Create LZMA2 reader for raw compressed data (not XZ format)
	lzma2Reader, err := lzma.NewReader2(bytes.NewReader(compressedData))
	if err != nil {
		return nil, fmt.Errorf("failed to create LZMA2 reader: %w", err)
	}

	// Decompress data
	var decompressed bytes.Buffer
	_, err = io.Copy(&decompressed, lzma2Reader)
	if err != nil {
		return nil, fmt.Errorf("LZMA2 decompression failed: %w", err)
	}

	return decompressed.Bytes(), nil
}

// verifyHash verifies the SHA256 hash of decompressed data
func verifyHash(data []byte, expectedHash string) bool {
	// Calculate SHA256 hash
	hash := sha256.Sum256(data)
	actualHash := hex.EncodeToString(hash[:])

	// Compare (case-insensitive)
	return strings.EqualFold(actualHash, expectedHash)
}
