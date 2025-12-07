// Package parser handles NTPI file parsing and region extraction
package parser

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"

	"github.com/YunWaiHe/ntpi-dumper-go/pkg/crypto"
	"github.com/YunWaiHe/ntpi-dumper-go/pkg/structures"
	"github.com/fatih/color"
)

// FileInfo represents metadata for a single file from FileIndex.xml
type FileInfo struct {
	Name                string `xml:"Name,attr"`
	FileSha256Hash      string `xml:"FileSha256Hash,attr"`
	PartitionSha256Hash string `xml:"PartitionSha256Hash,attr"`
	KeyIndex            int    `xml:"KeyIndex,attr"`
	IsSparse            string `xml:"IsSparse,attr"`
	IsEncrypted         string `xml:"IsEncrypted,attr"`
	IsCompressed        string `xml:"IsCompressed,attr"`
	PartitionLength     uint64 `xml:"PartitionLength,attr"`
	OriginalLength      uint64 `xml:"OriginalLength,attr"`
	Offset              uint64 `xml:"Offset,attr"`
	Length              uint64 `xml:"Length,attr"`
}

// FileIndex represents the root element of FileIndex.xml
type FileIndex struct {
	XMLName xml.Name   `xml:"fileinfo"`
	Files   []FileInfo `xml:"file"`
}

// ParseNTPIFile reads and parses an NTPI file, extracting all regions (Stage 1)
func ParseNTPIFile(filePath string, outputDir string) error {
	cyan := color.New(color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()

	fmt.Printf("%s\n", cyan("=== Stage 1: Parsing NTPI File ==="))

	// Read entire NTPI file into memory
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read NTPI file: %w", err)
	}

	fileSize := float64(len(fileData)) / (1024 * 1024)
	fmt.Printf("File size: %s\n", cyan(fmt.Sprintf("%.2f MB", fileSize)))

	// Parse NTPI header
	header, err := structures.ParseNTPIHeader(fileData)
	if err != nil {
		return fmt.Errorf("failed to parse NTPI header: %w", err)
	}

	fmt.Printf("NTPI Version: %s\n", green(header.Version()))

	// Get AES key dictionary for this version
	keyDict := structures.GetAESDictForVersion(header.VersionMajor, header.VersionMinor, header.VersionPatch)
	if keyDict == nil {
		fmt.Printf("%s\n", yellow("Warning: Unsupported firmware version, using default keys"))
		keyDict = structures.DefaultAESDict
	}

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Start extracting regions
	currentOffset := header.Size()
	currentRegion := header.FirstRegion
	regionCount := 0

	for {
		regionCount++
		regionName := structures.RegionName(currentRegion.RegionType)

		fmt.Printf("\n%s %s (Type=%d, Size=%d bytes)\n",
			cyan("Processing Region:"),
			green(regionName),
			currentRegion.RegionType,
			currentRegion.RegionSize,
		)

		// Extract region data
		nextOffset, nextRegion, err := extractRegion(fileData, currentRegion, currentOffset, outputDir, keyDict)
		if err != nil {
			return fmt.Errorf("failed to extract region %s: %w", regionName, err)
		}

		// Check if there are more regions
		if nextOffset == -1 || nextRegion == nil {
			break
		}

		currentOffset = nextOffset
		currentRegion = *nextRegion
	}

	fmt.Printf("\n%s\n", green(fmt.Sprintf("Successfully extracted %d regions", regionCount)))
	return nil
}

// extractRegion extracts and decrypts a single region
func extractRegion(fileData []byte, regionHeader structures.RegionHeader, offset int, outputDir string, keyDict *structures.AESKeyDict) (int, *structures.RegionHeader, error) {
	regionName := structures.RegionName(regionHeader.RegionType)

	// Validate region boundaries
	regionEnd := offset + int(regionHeader.RegionSize)
	if regionEnd > len(fileData) {
		return 0, nil, fmt.Errorf("region data out of bounds: offset=%d, size=%d, file_size=%d",
			offset, regionHeader.RegionSize, len(fileData))
	}

	// Extract region data
	regionData := fileData[offset:regionEnd]

	// Region6 contains encrypted file blocks, save as-is for later processing
	if regionHeader.RegionType == 6 {
		outputFile := filepath.Join(outputDir, "region6block.bin")
		if err := os.WriteFile(outputFile, regionData, 0644); err != nil {
			return 0, nil, fmt.Errorf("failed to save Region6: %w", err)
		}
		fmt.Printf("  Saved to: %s\n", outputFile)
		return -1, nil, nil
	}

	// Decrypt the region data
	decryptedData, err := crypto.DecryptRegionData(regionData, regionHeader.RegionType, keyDict)
	if err != nil {
		return 0, nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Parse region block header from decrypted data
	if len(decryptedData) < 40 {
		return 0, nil, fmt.Errorf("decrypted data too small for RegionBlockHeader: %d bytes", len(decryptedData))
	}

	blockHeader, err := structures.ParseRegionBlockHeader(decryptedData)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to parse region block header: %w", err)
	}

	// Extract actual data content
	dataOffset := 40 // Size of RegionBlockHeader
	dataEnd := dataOffset + int(blockHeader.RealSize)

	if dataEnd > len(decryptedData) {
		return 0, nil, fmt.Errorf("real data size exceeds decrypted buffer: real_size=%d, buffer_size=%d",
			blockHeader.RealSize, len(decryptedData))
	}

	actualData := decryptedData[dataOffset:dataEnd]

	// Save to file
	var outputFile string
	if regionHeader.RegionType == 4 {
		// KeyMap is binary
		outputFile = filepath.Join(outputDir, fmt.Sprintf("%s.bin", regionName))
	} else {
		// Others are XML
		outputFile = filepath.Join(outputDir, fmt.Sprintf("%s.xml", regionName))
	}

	if err := os.WriteFile(outputFile, actualData, 0644); err != nil {
		return 0, nil, fmt.Errorf("failed to save file: %w", err)
	}

	fmt.Printf("  Saved to: %s (%.2f KB)\n", outputFile, float64(len(actualData))/1024)

	// Check if there's a next region
	if blockHeader.NextHeader.RegionSize > 0 {
		nextOffset := offset + int(regionHeader.RegionSize)
		return nextOffset, &blockHeader.NextHeader, nil
	}

	return -1, nil, nil
}

// ParseFileIndex parses FileIndex.xml and returns a list of files
func ParseFileIndex(fileIndexPath string) ([]FileInfo, error) {
	data, err := os.ReadFile(fileIndexPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read FileIndex.xml: %w", err)
	}

	var fileIndex FileIndex
	if err := xml.Unmarshal(data, &fileIndex); err != nil {
		return nil, fmt.Errorf("failed to parse FileIndex.xml: %w", err)
	}

	return fileIndex.Files, nil
}
