// Package extractor - Large file segmentation and parallel processing
package extractor

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/YunWaiHe/ntpi-dumper-go/pkg/crypto"
	"github.com/YunWaiHe/ntpi-dumper-go/pkg/structures"
	"github.com/schollz/progressbar/v3"
)

// Segment represents a portion of a large file
type Segment struct {
	StartOffset     int
	EndOffset       int
	StartBlockIndex int
	NumBlocks       int
}

// processLargeFileSegmented processes large files (>=500MB) using segmentation
func processLargeFileSegmented(task FileTask) FileResult {
	file := task.FileInfo
	outputPath := filepath.Join(task.OutputDir, file.Name)

	// Create parent directories
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return FileResult{
			FileName: file.Name,
			Success:  false,
			Message:  fmt.Sprintf("failed to create directory: %v", err),
		}
	}

	// Split file into segments
	segments, err := splitFileIntoSegments(task, task.NumSegments)
	if err != nil {
		return FileResult{
			FileName: file.Name,
			Success:  false,
			Message:  fmt.Sprintf("failed to split file: %v", err),
		}
	}

	// Create per-file progress bar (exact payload-dumper-go style)
	totalBytes := int64(file.PartitionLength)
	var fileBar *progressbar.ProgressBar
	if task.ShowProgress {
		sizeStr := formatSizeSegment(file.PartitionLength)
		// Format: "filename (size) 100% |====| [speed MB/s]"
		// Align filename to 45 chars for better formatting
		descStr := fmt.Sprintf("%-45s", fmt.Sprintf("%s (%s)", truncateFileNameSegment(file.Name, 30), sizeStr))
		// Convert bytes to MB for display (divide by 1024*1024)
		totalMB := totalBytes / (1024 * 1024)
		if totalMB < 1 {
			totalMB = 1 // Avoid division by zero for small files
		}
		fileBar = progressbar.NewOptions64(totalBytes,
			progressbar.OptionSetDescription(descStr),
			progressbar.OptionSetWidth(50),
			progressbar.OptionShowBytes(true),
			progressbar.OptionSetPredictTime(false),
			progressbar.OptionThrottle(100*time.Millisecond),
			progressbar.OptionSetRenderBlankState(true),
			progressbar.OptionSetWriter(os.Stderr),
			progressbar.OptionOnCompletion(func() {
				fmt.Fprint(os.Stderr, "\n")
			}),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "=",
				SaucerHead:    "=",
				SaucerPadding: " ",
				BarStart:      "|",
				BarEnd:        "|",
			}),
		)
	}

	// Process segments in parallel
	segmentResults := make([][]byte, len(segments))
	segmentSizes := make([]int64, len(segments))
	var wg sync.WaitGroup
	errors := make(chan error, len(segments))
	progressMutex := &sync.Mutex{}
	processedBytes := int64(0)

	for i, segment := range segments {
		wg.Add(1)
		go func(idx int, seg Segment) {
			defer wg.Done()

			data, err := processSegment(task, seg)
			if err != nil {
				errors <- fmt.Errorf("segment %d: %w", idx, err)
				return
			}

			segmentResults[idx] = data
			segmentSizes[idx] = int64(len(data))

			// Update progress bar with actual bytes processed
			if fileBar != nil {
				progressMutex.Lock()
				processedBytes += int64(len(data))
				fileBar.Set64(processedBytes)
				progressMutex.Unlock()
			}
		}(i, segment)
	}

	wg.Wait()
	close(errors)

	// Finish progress bar
	if fileBar != nil {
		fileBar.Finish()
	}

	// Check for errors
	if len(errors) > 0 {
		err := <-errors
		return FileResult{
			FileName: file.Name,
			Success:  false,
			Message:  fmt.Sprintf("segment processing failed: %v", err),
		}
	}

	// Concatenate all segments
	var fileData bytes.Buffer
	for _, segData := range segmentResults {
		fileData.Write(segData)
	}

	finalData := fileData.Bytes()

	// Verify hash
	if !verifyHash(finalData, file.FileSha256Hash) {
		return FileResult{
			FileName: file.Name,
			Success:  false,
			Message:  "hash verification failed",
		}
	}

	// Write to file
	if err := os.WriteFile(outputPath, finalData, 0644); err != nil {
		return FileResult{
			FileName: file.Name,
			Success:  false,
			Message:  fmt.Sprintf("failed to write file: %v", err),
		}
	}

	return FileResult{
		FileName: file.Name,
		Success:  true,
		Message:  "OK (segmented)",
	}
}

// splitFileIntoSegments divides a large file into segments for parallel processing
func splitFileIntoSegments(task FileTask, numSegments int) ([]Segment, error) {
	file := task.FileInfo
	offsetStart := int(file.Offset)
	offsetEnd := offsetStart + int(file.Length)

	// Step 1: Scan all block boundaries
	type BlockBoundary struct {
		Offset          int
		BlockIndex      int
		AccumulatedSize uint64
	}

	var boundaries []BlockBoundary
	currentOffset := offsetStart
	blockIndex := 0
	accumulatedSize := uint64(0)

	for currentOffset < offsetEnd {
		// Validate header boundaries
		if currentOffset+112 > len(task.Region6Data) {
			break
		}

		// Parse block header
		header, err := structures.ParseNTEncodeHeader(task.Region6Data[currentOffset : currentOffset+112])
		if err != nil {
			break
		}

		// Record boundary
		boundaries = append(boundaries, BlockBoundary{
			Offset:          currentOffset,
			BlockIndex:      blockIndex,
			AccumulatedSize: accumulatedSize,
		})

		// Move to next block
		encryptedSize := int(header.OriginalSize)
		blockSize := 112 + encryptedSize
		currentOffset += blockSize
		blockIndex++

		// Accumulate decompressed size
		accumulatedSize += header.ProcessedSize
	}

	totalBlocks := len(boundaries)
	if totalBlocks == 0 {
		return nil, fmt.Errorf("no valid blocks found")
	}

	// Step 2: Divide blocks into balanced segments
	targetSizePerSegment := accumulatedSize / uint64(numSegments)

	var segments []Segment
	segmentStartIdx := 0
	currentSegmentSize := uint64(0)

	for i := 0; i < totalBlocks; i++ {
		if segmentStartIdx < len(boundaries) {
			currentSegmentSize = boundaries[i].AccumulatedSize - boundaries[segmentStartIdx].AccumulatedSize
		}

		shouldEndSegment := false
		if len(segments) < numSegments-1 {
			if currentSegmentSize >= targetSizePerSegment {
				shouldEndSegment = true
			}
		}

		if shouldEndSegment || i == totalBlocks-1 {
			startOffset := boundaries[segmentStartIdx].Offset
			startBlockIdx := boundaries[segmentStartIdx].BlockIndex

			var endOffset int
			var numBlocks int

			if i == totalBlocks-1 {
				endOffset = offsetEnd
				numBlocks = totalBlocks - segmentStartIdx
			} else {
				if i+1 < totalBlocks {
					endOffset = boundaries[i+1].Offset
				} else {
					endOffset = offsetEnd
				}
				numBlocks = i - segmentStartIdx + 1
			}

			segments = append(segments, Segment{
				StartOffset:     startOffset,
				EndOffset:       endOffset,
				StartBlockIndex: startBlockIdx,
				NumBlocks:       numBlocks,
			})

			segmentStartIdx = i + 1
			currentSegmentSize = 0
		}
	}

	return segments, nil
}

// processSegment processes a single segment of a large file
func processSegment(task FileTask, segment Segment) ([]byte, error) {
	var segmentData bytes.Buffer

	currentOffset := segment.StartOffset
	blockCount := 0

	for currentOffset < segment.EndOffset && blockCount < segment.NumBlocks {
		// Calculate key index
		keyIndex := task.FileInfo.KeyIndex + segment.StartBlockIndex + blockCount

		// Extract key
		key, err := crypto.ExtractKeyFromKeyMap(task.KeyMapData, keyIndex)
		if err != nil {
			return nil, fmt.Errorf("failed to extract key: %w", err)
		}

		// Decrypt block
		nextOffset, decryptedData, err := crypto.DecryptNTEncodeBlock(task.Region6Data, currentOffset, key)
		if err != nil {
			return nil, fmt.Errorf("decryption failed: %w", err)
		}

		// Decompress block
		decompressedData, err := decompressLZMA2(decryptedData)
		if err != nil {
			return nil, fmt.Errorf("decompression failed: %w", err)
		}

		segmentData.Write(decompressedData)

		currentOffset = nextOffset
		blockCount++
	}

	return segmentData.Bytes(), nil
}

// calculateOptimalSegments determines the optimal number of segments based on file size
func calculateOptimalSegments(fileSize uint64) int {
	const (
		MB = 1024 * 1024
		GB = 1024 * MB
	)

	switch {
	case fileSize < 500*MB:
		return 1 // Sequential
	case fileSize < 1*GB:
		return 4 // 2x original (was 2)
	case fileSize < 2*GB:
		return 8 // 2x original (was 4)
	case fileSize < 4*GB:
		return 12 // 2x original (was 6)
	default:
		return 16 // 2x original (was 8)
	}
}

// truncateFileNameSegment truncates a filename to a maximum length (for segment progress bars)
func truncateFileNameSegment(filename string, maxLen int) string {
	if len(filename) <= maxLen {
		return filename
	}
	// Keep the extension
	ext := filepath.Ext(filename)
	nameWithoutExt := filename[:len(filename)-len(ext)]

	if len(ext) >= maxLen-3 {
		return filename[:maxLen-3] + "..."
	}

	allowedLen := maxLen - len(ext) - 3
	return nameWithoutExt[:allowedLen] + "..." + ext
}

// formatSizeSegment formats a size in bytes to a human-readable string (for segment progress bars)
func formatSizeSegment(bytes uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.1f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.1f kB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
