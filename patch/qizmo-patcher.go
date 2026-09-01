package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// Types

// replacement describes one validated patch site in the executable.
type replacement struct {
	Name   string
	Offset int
	Before []byte
	After  []byte
}

type patchContext struct {
	output []byte
	state  any
}

// patch is one ordered transformation in a platform patch sequence.
type patch interface {
	fmt.Stringer
	apply(*patchContext) error
}

// bytePatch implements patch with validated, same-size byte replacements.
type bytePatch struct {
	Name         string
	Description  string
	Replacements []replacement
}

type patchResult struct {
	Output   []byte
	Changed  bool
	Platform string
	Steps    []string
}

// Shared patch policy

const (
	originalLimit = 196
	patchedLimit  = 1024
)

// Patch engine

// applyReplacement validates and applies one byte replacement.
func applyReplacement(
	output []byte, patchName string, replacement replacement,
) error {
	if len(replacement.Before) != len(replacement.After) {
		return fmt.Errorf(
			"%s/%s: replacement length is %d, want %d",
			patchName,
			replacement.Name,
			len(replacement.After),
			len(replacement.Before),
		)
	}

	end := replacement.Offset + len(replacement.Before)
	if replacement.Offset < 0 || end > len(output) {
		return fmt.Errorf(
			"%s/%s: offset %#x is outside the binary",
			patchName,
			replacement.Name,
			replacement.Offset,
		)
	}

	target := output[replacement.Offset:end]
	if !bytes.Equal(target, replacement.Before) {
		return fmt.Errorf(
			"%s/%s: unexpected bytes at offset %#x",
			patchName,
			replacement.Name,
			replacement.Offset,
		)
	}
	copy(target, replacement.After)
	return nil
}

func (current bytePatch) String() string {
	return current.Name + ": " + current.Description
}

func (current bytePatch) apply(context *patchContext) error {
	return applyBytePatch(context.output, current)
}

// applyBytePatch applies every byte replacement belonging to one patch.
func applyBytePatch(output []byte, current bytePatch) error {
	for _, replacement := range current.Replacements {
		replacementErr := applyReplacement(
			output, current.Name, replacement,
		)
		if replacementErr != nil {
			return replacementErr
		}
	}
	return nil
}

// verifyPatchedOutput catches accidental changes to a patch definition.
func verifyPatchedOutput(output []byte, expected string) error {
	got := digest(output)
	if got == expected {
		return nil
	}
	return fmt.Errorf(
		"internal error: patched sha256 is %s, want %s",
		got,
		expected,
	)
}

// applyPatchPlan consumes one ordered patch slice and validates its output.
func applyPatchPlan(
	context *patchContext,
	patches []patch,
	expected string,
) ([]byte, []string, error) {
	steps := make([]string, 0, len(patches))
	for _, current := range patches {
		step := current.String()
		if err := current.apply(context); err != nil {
			return nil, nil, fmt.Errorf(
				"%s: %w",
				step,
				err,
			)
		}
		steps = append(steps, step)
	}

	result := context.output
	if verifyErr := verifyPatchedOutput(result, expected); verifyErr != nil {
		return nil, nil, verifyErr
	}
	return result, steps, nil
}

func applyPatchSequence(
	input []byte,
	patches []patch,
	state any,
	expected string,
) ([]byte, []string, error) {
	context := &patchContext{
		output: bytes.Clone(input),
		state:  state,
	}
	return applyPatchPlan(
		context,
		patches,
		expected,
	)
}

// applyPatches delegates executable recognition and platform-specific
// preparation to the corresponding platform module.
func applyPatches(input []byte) (*patchResult, error) {
	inputDigest := digest(input)

	if result, recognized, err := patchLinux(input, inputDigest); recognized {
		return result, err
	}
	if result, recognized, err := patchWindows(input, inputDigest); recognized {
		return result, err
	}

	return nil, fmt.Errorf(
		"unsupported Qizmo binary (sha256 %s); "+
			"expected Qizmo 2.91 Linux or Windows",
		inputDigest,
	)
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Command-line interface

const patcherBanner = `
 +------------------------------------------------------------------+
 | QW QIZMO v2.91                                                   |
 | COMPATIBILITY FIXES BY OSCAR LINDERHOLM, 2026                    |
 +------------------------------------------------------------------+`

func printPatchReport(inputPath, outputPath string, input []byte, result *patchResult) {
	fmt.Println(patcherBanner)
	fmt.Printf("\n  INPUT   %s\n", inputPath)
	fmt.Printf("  OUTPUT  %s\n", outputPath)
	fmt.Printf("  FORMAT  %s\n", result.Platform)
	fmt.Printf("  SHA256  %s\n", digest(input))

	if result.Changed {
		fmt.Println()
		stepCount := len(result.Steps)
		for index, step := range result.Steps {
			fmt.Printf(
				"  [%02d/%02d] %s\n",
				index+1,
				stepCount,
				step,
			)
		}
	} else {
		fmt.Println("\n  already patched: no changes required")
	}

	fmt.Printf("\n  VERIFY  %s\n", digest(result.Output))
	fmt.Printf("  WROTE   %s\n", outputPath)
}

func main() {
	inputPath := flag.String(
		"input", "", "original Qizmo 2.91 Linux or Windows binary",
	)
	outputPath := flag.String("output", "", "patched output binary")
	flag.Parse()
	if flag.NArg() != 0 {
		fail("unexpected positional arguments")
	}
	if *inputPath == "" {
		fail("-input is required")
	}
	if *outputPath == "" {
		fail("-output is required")
	}

	input, err := os.ReadFile(*inputPath)
	if err != nil {
		fail("read %s: %v", *inputPath, err)
	}
	result, err := applyPatches(input)
	if err != nil {
		fail("patch %s: %v", *inputPath, err)
	}
	mode := os.FileMode(0o755)
	if result.Platform == "windows" {
		mode = 0o644
	}
	if err := writeOutput(*outputPath, result.Output, mode); err != nil {
		fail("write %s: %v", *outputPath, err)
	}
	printPatchReport(*inputPath, *outputPath, input, result)
}

func createTemporaryOutput(
	dir string, data []byte, mode os.FileMode,
) (name string, err error) {
	tmp, err := os.CreateTemp(dir, ".qizmo-patch-*")
	if err != nil {
		return "", err
	}
	name = tmp.Name()
	defer func() {
		closeErr := tmp.Close()
		if err == nil && closeErr != nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(name)
		}
	}()

	if _, err = tmp.Write(data); err != nil {
		return name, err
	}
	if err = tmp.Chmod(mode); err != nil {
		return name, err
	}
	return name, nil
}

func writeOutput(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmpName, err := createTemporaryOutput(dir, data, mode)
	if err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

func fail(format string, args ...any) {
	fmt.Fprint(os.Stderr, "\n  [ ABORT ] qizmo-patch :: ")
	fmt.Fprintf(os.Stderr, format, args...)
	fmt.Fprint(os.Stderr, "\n\n")
	os.Exit(1)
}
