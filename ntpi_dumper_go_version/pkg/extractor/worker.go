// Package extractor handles concurrent file extraction and decompression
package extractor

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/YunWaiHe/ntpi-dumper-go/pkg/crypto"
	"github.com/YunWaiHe/ntpi-dumper-go/pkg/parser"
	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
)

// FileTask represents a file extraction task
type FileTask struct {
	FileInfo     parser.FileInfo
	Region6Data  []byte
	KeyMapData   []byte
	OutputDir    string
	UseSegmented bool
	NumSegments  int
	ShowProgress bool // Whether to show per-file progress bar
}

// FileResult represents the result of a file extraction
type FileResult struct {
	FileName string
	Success  bool
	Message  string
	Duration time.Duration
}

// ExtractFiles performs Stage 2: concurrent extraction and decompression
func ExtractFiles(tempDir, outputDir string, numWorkers int) error {
	cyan := color.New(color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()

	fmt.Printf("\n%s\n", cyan("=== Stage 2: Extracting and Decompressing Files ==="))

	// Auto-detect optimal worker count if not specified
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
		if numWorkers > 4 {
			numWorkers = 4 // Cap at 4 for balanced performance
		}
	}

	fmt.Printf("Worker goroutines: %s\n", cyan(fmt.Sprintf("%d", numWorkers)))

	// Load FileIndex.xml
	fileIndexPath := filepath.Join(tempDir, "FileIndex.xml")
	files, err := parser.ParseFileIndex(fileIndexPath)
	if err != nil {
		return fmt.Errorf("failed to parse FileIndex.xml: %w", err)
	}

	fmt.Printf("Total files: %s\n", cyan(fmt.Sprintf("%d", len(files))))

	// Load Region6 data
	region6Path := filepath.Join(tempDir, "region6block.bin")
	region6Data, err := os.ReadFile(region6Path)
	if err != nil {
		return fmt.Errorf("failed to load Region6 data: %w", err)
	}

	fmt.Printf("Region6 size: %s\n", cyan(fmt.Sprintf("%.2f MB", float64(len(region6Data))/(1024*1024))))

	// Load KeyMap data
	keyMapPath := filepath.Join(tempDir, "KeyMap.bin")
	keyMapData, err := os.ReadFile(keyMapPath)
	if err != nil {
		return fmt.Errorf("failed to load KeyMap: %w", err)
	}

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Create tasks
	tasks := make([]FileTask, len(files))
	totalSize := uint64(0)

	for i, file := range files {
		numSegments := calculateOptimalSegments(file.PartitionLength)
		tasks[i] = FileTask{
			FileInfo:     file,
			Region6Data:  region6Data,
			KeyMapData:   keyMapData,
			OutputDir:    outputDir,
			UseSegmented: numSegments > 1,
			NumSegments:  numSegments,
			ShowProgress: true, // Enable per-file progress bars
		}
		totalSize += file.PartitionLength
	}

	fmt.Printf("Total data size: %s\n\n", cyan(fmt.Sprintf("%.2f GB", float64(totalSize)/(1024*1024*1024))))
	fmt.Println("Found partitions:")

	// Print all partitions with their sizes
	for _, file := range files {
		sizeStr := formatSize(file.PartitionLength)
		fmt.Printf("%s (%s)\n", file.Name, sizeStr)
	}
	fmt.Println()

	// Process files with worker pool
	startTime := time.Now()
	results := processFilesParallel(tasks, numWorkers)
	totalDuration := time.Since(startTime)

	// Analyze results
	successCount := 0
	failedFiles := []string{}

	for _, result := range results {
		if result.Success {
			successCount++
		} else {
			failedFiles = append(failedFiles, result.FileName)
			fmt.Printf("\n%s %s: %s\n", red("Failed"), result.FileName, result.Message)
		}
	}

	// Print summary
	fmt.Printf("\n%s\n", cyan("=== Extraction Summary ==="))
	fmt.Printf("Successful: %s / %d\n", green(fmt.Sprintf("%d", successCount)), len(files))
	if len(failedFiles) > 0 {
		fmt.Printf("Failed: %s\n", red(fmt.Sprintf("%d", len(failedFiles))))
		for _, name := range failedFiles {
			fmt.Printf("  - %s\n", name)
		}
	}
	totalSeconds := totalDuration.Seconds()
	totalMinutes := totalDuration.Minutes()
	fmt.Printf("Total time: %s (%.2f seconds / %.2f minutes, %.2f files/sec)\n",
		cyan(totalDuration.Round(time.Second).String()),
		totalSeconds, totalMinutes,
		float64(len(files))/totalSeconds)

	if successCount != len(files) {
		return fmt.Errorf("%d files failed to extract", len(failedFiles))
	}

	return nil
}

// processFilesParallel processes files using a worker pool with per-file progress bars
func processFilesParallel(tasks []FileTask, numWorkers int) []FileResult {
	jobs := make(chan FileTask, len(tasks))
	results := make(chan FileResult, len(tasks))

	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(i, jobs, results, &wg)
	}

	// Send tasks
	for _, task := range tasks {
		jobs <- task
	}
	close(jobs)

	// Wait for completion
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var allResults []FileResult
	for result := range results {
		allResults = append(allResults, result)
	}

	return allResults
}

// worker processes file extraction tasks
func worker(id int, jobs <-chan FileTask, results chan<- FileResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for task := range jobs {
		startTime := time.Now()
		var result FileResult

		if task.UseSegmented {
			// Large file: use segmented parallel processing
			result = processLargeFileSegmented(task)
		} else {
			// Small file: sequential processing
			result = processFileSequential(task)
		}

		result.Duration = time.Since(startTime)
		results <- result
	}
}

// Forward declaration - implemented in segment.go
// processLargeFileSegmented is defined in segment.go

// processFileSequential processes a file sequentially (for files < 500MB)
func processFileSequential(task FileTask) FileResult {
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

	// Calculate total size and offsets
	currentOffset := int(file.Offset)
	endOffset := currentOffset + int(file.Length)
	totalBytes := int64(file.PartitionLength)

	// Create per-file progress bar (exact payload-dumper-go style)
	var fileBar *progressbar.ProgressBar
	if task.ShowProgress {
		sizeStr := formatSize(file.PartitionLength)
		// Format: "filename (size) 100% |====| [speed MB/s]"
		// Align filename to 45 chars for better formatting
		descStr := fmt.Sprintf("%-45s", fmt.Sprintf("%s (%s)", truncateFileName(file.Name, 30), sizeStr))
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

	// Process all blocks sequentially
	var fileData bytes.Buffer
	blockIndex := 0
	processedBytes := int64(0)

	for currentOffset < endOffset {
		// Get key for this block
		keyIndex := file.KeyIndex + blockIndex
		key, err := crypto.ExtractKeyFromKeyMap(task.KeyMapData, keyIndex)
		if err != nil {
			return FileResult{
				FileName: file.Name,
				Success:  false,
				Message:  fmt.Sprintf("failed to extract key: %v", err),
			}
		}

		// Decrypt block
		nextOffset, decryptedData, err := crypto.DecryptNTEncodeBlock(task.Region6Data, currentOffset, key)
		if err != nil {
			return FileResult{
				FileName: file.Name,
				Success:  false,
				Message:  fmt.Sprintf("decryption failed at block %d: %v", blockIndex, err),
			}
		}

		// Decompress block
		decompressedData, err := decompressLZMA2(decryptedData)
		if err != nil {
			return FileResult{
				FileName: file.Name,
				Success:  false,
				Message:  fmt.Sprintf("decompression failed at block %d: %v", blockIndex, err),
			}
		}

		fileData.Write(decompressedData)

		// Update progress bar with actual decompressed bytes
		processedBytes += int64(len(decompressedData))
		if fileBar != nil {
			fileBar.Set64(processedBytes)
		}

		currentOffset = nextOffset
		blockIndex++
	}

	// Finish progress bar
	if fileBar != nil {
		fileBar.Finish()
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
		Message:  "OK",
	}
}

// estimateBlockCount estimates the number of blocks in a file
func estimateBlockCount(fileLength uint64) int {
	// Average block size is approximately 1MB after decompression
	// This is a rough estimate for progress bar purposes
	avgBlockSize := uint64(1024 * 1024) // 1MB
	estimatedBlocks := int(fileLength / avgBlockSize)
	if estimatedBlocks < 1 {
		estimatedBlocks = 1
	}
	return estimatedBlocks
}

// truncateFileName truncates a filename to a maximum length
func truncateFileName(filename string, maxLen int) string {
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

// formatSize formats a size in bytes to a human-readable string
func formatSize(bytes uint64) string {
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

// Continue in next file...
