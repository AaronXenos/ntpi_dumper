//go:build cgo
// +build cgo

// Package extractor - High-performance LZMA2 decompression using CGO
// Based on payload-dumper-go approach: https://github.com/ssut/payload-dumper-go
package extractor

/*
#cgo LDFLAGS: -llzma
#include <lzma.h>
#include <stdlib.h>

// Decompress LZMA2 data using liblzma (C library)
int decompress_lzma2(const uint8_t *in_data, size_t in_size, uint8_t **out_data, size_t *out_size) {
    lzma_stream strm = LZMA_STREAM_INIT;
    lzma_ret ret;

    // Initialize LZMA2 decoder with raw mode (no XZ container)
    ret = lzma_raw_decoder(&strm, (lzma_filter[]){
        {
            .id = LZMA_FILTER_LZMA2,
            .options = &(lzma_options_lzma){
                .dict_size = LZMA_DICT_SIZE_DEFAULT,
            },
        },
        { .id = LZMA_VLI_UNKNOWN, .options = NULL },
    });

    if (ret != LZMA_OK) {
        return -1;
    }

    // Allocate output buffer (estimate: 3x input size)
    size_t out_buf_size = in_size * 3;
    uint8_t *out_buf = (uint8_t*)malloc(out_buf_size);
    if (out_buf == NULL) {
        lzma_end(&strm);
        return -2;
    }

    strm.next_in = in_data;
    strm.avail_in = in_size;
    strm.next_out = out_buf;
    strm.avail_out = out_buf_size;

    // Decompress
    while (1) {
        ret = lzma_code(&strm, LZMA_FINISH);

        if (ret == LZMA_STREAM_END) {
            break;
        }

        if (ret == LZMA_BUF_ERROR) {
            // Need more output space
            size_t new_size = out_buf_size * 2;
            uint8_t *new_buf = (uint8_t*)realloc(out_buf, new_size);
            if (new_buf == NULL) {
                free(out_buf);
                lzma_end(&strm);
                return -2;
            }

            strm.next_out = new_buf + (out_buf_size - strm.avail_out);
            strm.avail_out += out_buf_size;
            out_buf_size = new_size;
            out_buf = new_buf;
            continue;
        }

        if (ret != LZMA_OK) {
            free(out_buf);
            lzma_end(&strm);
            return -3;
        }
    }

    *out_size = out_buf_size - strm.avail_out;
    *out_data = out_buf;

    lzma_end(&strm);
    return 0;
}
*/
import "C"
import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"unsafe"

	"github.com/YunWaiHe/ntpi-dumper-go/pkg/structures"
	"github.com/ulikunitz/xz/lzma"
)

// useCGO determines whether to use CGO-based decompression
// Set to true for production (10-20x faster), false for pure Go (portable)
const useCGO = true

// decompressLZMA2 decompresses LZMA2-compressed data from a decrypted NTEncode block
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

	// Use CGO implementation for production (10-20x faster)
	if useCGO {
		return decompressLZMA2CGO(compressedData)
	}

	// Fallback to pure Go implementation (portable but slower)
	return decompressLZMA2PureGo(compressedData)
}

// decompressLZMA2CGO uses liblzma (C library) for high-performance decompression
func decompressLZMA2CGO(compressedData []byte) ([]byte, error) {
	var outData *C.uint8_t
	var outSize C.size_t

	inData := (*C.uint8_t)(unsafe.Pointer(&compressedData[0]))
	inSize := C.size_t(len(compressedData))

	ret := C.decompress_lzma2(inData, inSize, &outData, &outSize)
	if ret != 0 {
		return nil, fmt.Errorf("CGO LZMA2 decompression failed with code %d", ret)
	}

	// Convert C memory to Go slice
	decompressed := C.GoBytes(unsafe.Pointer(outData), C.int(outSize))

	// Free C memory
	C.free(unsafe.Pointer(outData))

	return decompressed, nil
}

// decompressLZMA2PureGo uses pure Go implementation (slower but portable)
func decompressLZMA2PureGo(compressedData []byte) ([]byte, error) {
	// Create LZMA2 reader for raw compressed data (not XZ format)
	lzma2Reader, err := lzma.NewReader2(bytes.NewReader(compressedData))
	if err != nil {
		return nil, fmt.Errorf("failed to create LZMA2 reader: %w", err)
	}

	// Decompress data
	var decompressed bytes.Buffer
	_, err = decompressed.ReadFrom(lzma2Reader)
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
