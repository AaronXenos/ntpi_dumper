// Package crypto provides AES encryption/decryption utilities for NTPI files
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"

	"github.com/YunWaiHe/ntpi-dumper-go/pkg/structures"
)

// DecryptAESCBC decrypts data using AES-CBC mode
func DecryptAESCBC(encryptedData, key, iv []byte) ([]byte, error) {
	// Use zero-filled keys if not provided
	if key == nil {
		key = make([]byte, 32)
	}
	if iv == nil {
		iv = make([]byte, 16)
	}

	// Validate key and IV sizes
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("invalid key size: %d (must be 16, 24, or 32)", len(key))
	}
	if len(iv) != 16 {
		return nil, fmt.Errorf("invalid IV size: %d (must be 16)", len(iv))
	}

	// Validate encrypted data size (must be multiple of block size)
	if len(encryptedData)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("encrypted data size is not a multiple of AES block size")
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create CBC decrypter
	mode := cipher.NewCBCDecrypter(block, iv)

	// Decrypt in-place
	decryptedData := make([]byte, len(encryptedData))
	mode.CryptBlocks(decryptedData, encryptedData)

	// Try to remove PKCS7 padding
	decryptedData = removePKCS7Padding(decryptedData)

	return decryptedData, nil
}

// removePKCS7Padding removes PKCS7 padding from decrypted data
func removePKCS7Padding(data []byte) []byte {
	if len(data) == 0 {
		return data
	}

	// Get padding length from last byte
	paddingLen := int(data[len(data)-1])

	// Validate padding length
	if paddingLen == 0 || paddingLen > aes.BlockSize || paddingLen > len(data) {
		return data // Invalid padding, return as-is
	}

	// Verify all padding bytes are correct
	for i := len(data) - paddingLen; i < len(data); i++ {
		if data[i] != byte(paddingLen) {
			return data // Invalid padding, return as-is
		}
	}

	// Remove padding
	return data[:len(data)-paddingLen]
}

// GetKeyIVForRegion returns the AES key and IV for a specific region type
func GetKeyIVForRegion(regionType uint64, keyDict *structures.AESKeyDict) ([]byte, []byte, error) {
	keyHex := keyDict.GetKeyForRegion(regionType)
	ivHex := keyDict.GetIVForRegion(regionType)

	if keyHex == "" || ivHex == "" {
		return nil, nil, fmt.Errorf("key or IV not found for region %d", regionType)
	}

	// Decode hex strings to bytes
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode key hex: %w", err)
	}

	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode IV hex: %w", err)
	}

	return key, iv, nil
}

// DecryptRegionData decrypts a region using the appropriate key from keyDict
func DecryptRegionData(encryptedData []byte, regionType uint64, keyDict *structures.AESKeyDict) ([]byte, error) {
	key, iv, err := GetKeyIVForRegion(regionType, keyDict)
	if err != nil {
		return nil, err
	}

	return DecryptAESCBC(encryptedData, key, iv)
}
