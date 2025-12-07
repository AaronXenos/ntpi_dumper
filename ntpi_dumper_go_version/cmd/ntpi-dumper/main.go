// NTPI Dumper Go - High-performance firmware extraction tool
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/YunWaiHe/ntpi-dumper-go/pkg/extractor"
	"github.com/YunWaiHe/ntpi-dumper-go/pkg/parser"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const (
	Version     = "0.2.0"
	Description = "High-performance NTPI firmware extraction tool"
	Author      = "YunWaiHe"
)

var (
	inputFile  string
	outputDir  string
	numWorkers int
	keepTemp   bool
)

var rootCmd = &cobra.Command{
	Use:   "ntpi-dumper [file.ntpi]",
	Short: Description,
	Long: fmt.Sprintf(`%s v%s

Extracts and decompresses firmware files from Nothing Phone NTPI archives.
Features intelligent optimization for large files with multi-threaded segmentation.

Author: %s`, Description, Version, Author),
	Args: cobra.MaximumNArgs(1),
	Run:  runExtraction,
}

func init() {
	rootCmd.Flags().StringVarP(&inputFile, "file", "f", "", "Input NTPI file path")
	rootCmd.Flags().StringVarP(&outputDir, "output", "o", "", "Output directory (default: <filename>_extracted)")
	rootCmd.Flags().IntVarP(&numWorkers, "workers", "w", 0, "Number of worker goroutines (default: auto)")
	rootCmd.Flags().BoolVarP(&keepTemp, "keep-temp", "k", false, "Keep temporary files for debugging")
	rootCmd.Version = Version
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runExtraction(cmd *cobra.Command, args []string) {
	cyan := color.New(color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()

	// Print banner (aligned)
	fmt.Println(cyan("╔═══════════════════════════════════════════════════╗"))
	fmt.Printf("%s %-49s %s\n", cyan("║"), green("  NTPI Dumper Go - High Performance Edition"), cyan("║"))
	fmt.Printf("%s %-49s %s\n", cyan("║"), fmt.Sprintf("  Version %s", Version), cyan("║"))
	fmt.Println(cyan("╚═══════════════════════════════════════════════════╝"))
	fmt.Println()

	// Determine input file
	if len(args) > 0 {
		inputFile = args[0]
	}

	if inputFile == "" {
		fmt.Println(yellow("Usage: Drag and drop an NTPI file onto this executable, or use:"))
		fmt.Println("  ntpi-dumper <file.ntpi>")
		fmt.Println("  ntpi-dumper -f <file.ntpi> [-o output_dir] [-w workers]")
		fmt.Println()
		fmt.Println(green("Features: 3-5x faster than Python with goroutine-based parallelism"))
		fmt.Println()
		fmt.Println("Press Enter to exit...")
		fmt.Scanln()
		os.Exit(1)
	}

	// Validate input file
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		fmt.Printf("%s Input file not found: %s\n", red("Error:"), inputFile)
		fmt.Println("Press Enter to exit...")
		fmt.Scanln()
		os.Exit(1)
	}

	// Determine output directory
	if outputDir == "" {
		baseName := filepath.Base(inputFile)
		ext := filepath.Ext(baseName)
		nameWithoutExt := baseName[:len(baseName)-len(ext)]
		outputDir = filepath.Join(filepath.Dir(inputFile), nameWithoutExt+"_extracted")
	}

	// Create temporary directory
	tempDir := ".temp"
	if err := os.RemoveAll(tempDir); err != nil {
		fmt.Printf("%s Failed to clean temp directory: %v\n", red("Error:"), err)
	}
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		fmt.Printf("%s Failed to create temp directory: %v\n", red("Error:"), err)
		fmt.Println("Press Enter to exit...")
		fmt.Scanln()
		os.Exit(1)
	}

	// Start timing
	totalStart := time.Now()

	defer func() {
		// Cleanup temporary files
		if !keepTemp {
			os.RemoveAll(tempDir)
		} else {
			absTemp, _ := filepath.Abs(tempDir)
			fmt.Printf("%s\n", yellow(fmt.Sprintf("Temporary files kept in: %s", absTemp)))
		}
	}()

	// Stage 1: Parse NTPI file and extract regions
	fmt.Printf("Input file: %s\n", cyan(inputFile))
	fmt.Printf("Output directory: %s\n", cyan(outputDir))
	fmt.Println()

	if err := parser.ParseNTPIFile(inputFile, tempDir); err != nil {
		fmt.Printf("\n%s %v\n", red("Stage 1 Failed:"), err)
		fmt.Println("Press Enter to exit...")
		fmt.Scanln()
		os.Exit(1)
	}

	// Stage 2: Extract and decompress all files from Region6
	if err := extractor.ExtractFiles(tempDir, outputDir, numWorkers); err != nil {
		fmt.Printf("\n%s %v\n", red("Stage 2 Failed:"), err)
		fmt.Println("Press Enter to exit...")
		fmt.Scanln()
		os.Exit(1)
	}

	// Move configuration XMLs to output directory
	fmt.Printf("\n%s\n", cyan("Moving configuration files..."))
	for _, filename := range []string{"Patch.xml", "RawProgram.xml"} {
		srcPath := filepath.Join(tempDir, filename)
		destPath := filepath.Join(outputDir, filename)
		if _, err := os.Stat(srcPath); err == nil {
			if err := os.Rename(srcPath, destPath); err != nil {
				fmt.Printf("%s Failed to move %s: %v\n", red("Warning:"), filename, err)
			}
		}
	}

	// Print final summary
	totalElapsed := time.Since(totalStart)
	totalSeconds := totalElapsed.Seconds()
	totalMinutes := totalElapsed.Minutes()

	fmt.Println()
	fmt.Println(green("╔═══════════════════════════════════════════════════╗"))
	fmt.Printf("%s %-49s %s\n", green("║"), cyan("  All files extracted successfully!"), green("║"))
	fmt.Println(green("╚═══════════════════════════════════════════════════╝"))
	fmt.Println()
	fmt.Printf("Output directory: %s\n", green(outputDir))
	fmt.Printf("Total time: %s (%.2f seconds / %.2f minutes)\n",
		cyan(totalElapsed.Round(time.Second).String()), totalSeconds, totalMinutes)
	fmt.Println()
	fmt.Println("Press Enter to exit...")
	fmt.Scanln()
}
