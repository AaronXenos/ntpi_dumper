// Package crypto - KeyMap handling utilities
package crypto

import (
	"fmt"

	"github.com/YunWaiHe/ntpi-dumper-go/pkg/structures"
)

// ExtractKeyFromKeyMap extracts a 32-byte AES key from the keymap at the specified index
// Each file block uses a different key, calculated by: key = keymap[keyIndex * 32 : keyIndex * 32 + 32]
func ExtractKeyFromKeyMap(keymapData []byte, keyIndex int) ([]byte, error) {
	if keymapData == nil || len(keymapData) == 0 {
		return nil, fmt.Errorf("keymap data is empty")
	}

	// Calculate byte offset (32 bytes per key)
	keyOffset := keyIndex * 32

	// Wrap around if index exceeds keymap size
	if keyOffset >= len(keymapData) {
		keyOffset = keyOffset % len(keymapData)
	}

	// Ensure we don't read past the end
	if keyOffset+32 > len(keymapData) {
		// Wrap around and concatenate
		firstPart := keymapData[keyOffset:]
		remaining := 32 - len(firstPart)
		secondPart := keymapData[:remaining]
		key := make([]byte, 32)
		copy(key, firstPart)
		copy(key[len(firstPart):], secondPart)
		return key, nil
	}

	// Extract 32-byte key
	key := make([]byte, 32)
	copy(key, keymapData[keyOffset:keyOffset+32])

	return key, nil
}

// DecryptNTEncodeBlock decrypts a single NTEncode block from Region6 data
func DecryptNTEncodeBlock(region6Data []byte, offset int, key []byte) (int, []byte, error) {
	// Validate offset
	if offset >= len(region6Data) {
		return 0, nil, fmt.Errorf("offset %d exceeds data size %d", offset, len(region6Data))
	}

	// Parse NTEncode header
	headerSize := 112
	if offset+headerSize > len(region6Data) {
		return 0, nil, fmt.Errorf("not enough data for NTEncode header at offset %d", offset)
	}

	header, err := structures.ParseNTEncodeHeader(region6Data[offset : offset+headerSize])
	if err != nil {
		return 0, nil, fmt.Errorf("failed to parse NTEncode header: %w", err)
	}

	// Extract encrypted data
	dataOffset := offset + headerSize
	encryptedSize := int(header.OriginalSize)

	if dataOffset+encryptedSize > len(region6Data) {
		return 0, nil, fmt.Errorf("encrypted data exceeds region6 bounds")
	}

	encryptedData := region6Data[dataOffset : dataOffset+encryptedSize]

	// Get IV from header (first 16 bytes)
	iv := header.GetIV()

	// Decrypt using AES-CBC
	decryptedData, err := DecryptAESCBC(encryptedData, key, iv)
	if err != nil {
		return 0, nil, fmt.Errorf("AES decryption failed: %w", err)
	}

	// Calculate next block offset
	nextOffset := dataOffset + encryptedSize

	return nextOffset, decryptedData, nil
}
