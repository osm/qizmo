package main

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"math/bits"
)

// Types

type protectedPE struct {
	input     []byte
	file      *pe.File
	imageBase uint32
}

type windowsPELockPatch struct{}

type peLockSkipRange struct {
	start uint32
	end   uint32
}

type peLockDirectories struct {
	importRVA      uint32
	importSize     uint32
	relocationRVA  uint32
	relocationSize uint32
}

type decryptedSection struct {
	section *pe.Section
	data    []byte
}

type peLockPayload struct {
	sections       []decryptedSection
	importRVA      uint32
	importSize     uint32
	relocationRVA  uint32
	relocationSize uint32
}

// Constants

const (
	windowsQizmo291ImageBase = uint32(0x01000000)

	peLockLoaderMinimumSize = 0x2816
	peLockSectionMultiplier = uint32(0x1268)
)

// Patch stage

func (windowsPELockPatch) String() string {
	return "pelock: decode the PELOCKnt v2.04 layer"
}

func (windowsPELockPatch) apply(context *patchContext) error {
	state, err := windowsState(context)
	if err != nil {
		return err
	}
	return state.decodePELock()
}

func (state *windowsUnlockState) decodePELock() error {
	peFile, err := pe.NewFile(bytes.NewReader(state.input))
	if err != nil {
		return fmt.Errorf("parse protected PE: %w", err)
	}
	state.protected = &protectedPE{
		input: state.input,
		file:  peFile,
	}

	optionalHeader, ok := peFile.OptionalHeader.(*pe.OptionalHeader32)
	if !ok {
		return fmt.Errorf("protected executable is not PE32")
	}
	if peFile.FileHeader.Machine != pe.IMAGE_FILE_MACHINE_I386 {
		return fmt.Errorf(
			"protected executable has unsupported PE machine %#x",
			peFile.FileHeader.Machine,
		)
	}
	if optionalHeader.ImageBase != windowsQizmo291ImageBase {
		return fmt.Errorf(
			"protected executable has image base %#x, want %#x",
			optionalHeader.ImageBase,
			windowsQizmo291ImageBase,
		)
	}

	state.protected.imageBase = optionalHeader.ImageBase
	state.peLock, err = unpackPELock(state.protected)
	if err != nil {
		return err
	}
	return nil
}

func (image *protectedPE) rawSectionData(section *pe.Section) ([]byte, error) {
	start := uint64(section.Offset)
	end := start + uint64(section.Size)
	if start > uint64(len(image.input)) ||
		end > uint64(len(image.input)) ||
		end < start {
		return nil, fmt.Errorf(
			"section %q raw range [%#x,%#x) is outside the %#x-byte file",
			section.Name, start, end, len(image.input),
		)
	}
	return image.input[start:end], nil
}

// PELOCKnt v2.04 outer layer

func unpackPELock(image *protectedPE) (*peLockPayload, error) {
	loaderSection, loader, err := preparePELockLoader(image)
	if err != nil {
		return nil, err
	}
	sectionKey := derivePELockSectionKey(loader)
	directories, err := readPELockDirectories(image, loader)
	if err != nil {
		return nil, err
	}
	sections, err := decryptPELockSections(
		image,
		loaderSection,
		loader,
		sectionKey,
		readPELockSkipRanges(loader),
	)
	if err != nil {
		return nil, err
	}
	return &peLockPayload{
		sections:       sections,
		importRVA:      directories.importRVA,
		importSize:     directories.importSize,
		relocationRVA:  directories.relocationRVA,
		relocationSize: directories.relocationSize,
	}, nil
}

func preparePELockLoader(
	image *protectedPE,
) (*pe.Section, []byte, error) {
	if len(image.file.Sections) < 2 {
		return nil, nil, fmt.Errorf(
			"PELOCKnt image has only %d section(s)",
			len(image.file.Sections),
		)
	}
	loaderSection := image.file.Sections[len(image.file.Sections)-1]
	optionalHeader := image.file.OptionalHeader.(*pe.OptionalHeader32)
	if optionalHeader.AddressOfEntryPoint != loaderSection.VirtualAddress {
		return nil, nil, fmt.Errorf(
			"protected entry-point RVA %#x does not begin at "+
				"the last section RVA %#x",
			optionalHeader.AddressOfEntryPoint,
			loaderSection.VirtualAddress,
		)
	}
	encryptedLoader, err := image.rawSectionData(loaderSection)
	if err != nil {
		return nil, nil, err
	}
	if len(encryptedLoader) < peLockLoaderMinimumSize {
		return nil, nil, fmt.Errorf(
			"PELOCKnt loader has %#x bytes; need at least %#x",
			len(encryptedLoader),
			peLockLoaderMinimumSize,
		)
	}
	loader := append([]byte(nil), encryptedLoader...)
	if err := decryptPELockLoader(loader); err != nil {
		return nil, nil, err
	}
	return loaderSection, loader, nil
}

func derivePELockSectionKey(loader []byte) uint32 {
	adjustment := binary.LittleEndian.Uint32(loader[0x2812:])
	for offset, count := 0x313, 0; count < 0x93f; offset, count =
		offset+4, count+1 {
		adjustment ^= binary.LittleEndian.Uint32(loader[offset:])
	}
	adjustment >>= 0x16
	return binary.LittleEndian.Uint32(loader[0x21a5:]) + adjustment
}

func readPELockDirectories(
	image *protectedPE,
	loader []byte,
) (peLockDirectories, error) {
	imageBase := binary.LittleEndian.Uint32(loader[0x2565:])
	if imageBase != image.imageBase {
		return peLockDirectories{}, fmt.Errorf(
			"decrypted PELOCKnt image base %#x does not match PE header %#x",
			imageBase,
			image.imageBase,
		)
	}
	importRVA := binary.LittleEndian.Uint32(loader[0x2569:])
	importEnd := binary.LittleEndian.Uint32(loader[0x256d:])
	relocationRVA := binary.LittleEndian.Uint32(loader[0x2571:])
	relocationEnd := binary.LittleEndian.Uint32(loader[0x2575:])
	if importEnd < importRVA || relocationEnd < relocationRVA {
		return peLockDirectories{}, fmt.Errorf(
			"decrypted PELOCKnt directory metadata contains a reversed range",
		)
	}
	return peLockDirectories{
		importRVA:      importRVA,
		importSize:     importEnd - importRVA,
		relocationRVA:  relocationRVA,
		relocationSize: relocationEnd - relocationRVA,
	}, nil
}

func readPELockSkipRanges(loader []byte) []peLockSkipRange {
	data := loader[0x2579:]
	ranges := []peLockSkipRange{
		{
			start: binary.LittleEndian.Uint32(data[0:]),
			end:   binary.LittleEndian.Uint32(data[4:]),
		},
		{
			start: binary.LittleEndian.Uint32(data[8:]),
			end:   binary.LittleEndian.Uint32(data[12:]),
		},
		{
			start: binary.LittleEndian.Uint32(data[16:]),
			end:   binary.LittleEndian.Uint32(data[20:]),
		},
		{
			start: binary.LittleEndian.Uint32(data[32:]),
			end:   binary.LittleEndian.Uint32(data[36:]),
		},
	}
	for index := range ranges {
		if ranges[index].end < ranges[index].start {
			ranges[index].start, ranges[index].end =
				ranges[index].end, ranges[index].start
		}
	}
	return ranges
}

func decryptPELockSections(
	image *protectedPE,
	loaderSection *pe.Section,
	loader []byte,
	sectionKey uint32,
	skipRanges []peLockSkipRange,
) ([]decryptedSection, error) {
	var sections []decryptedSection
	for tableOffset := 0x25af; ; tableOffset += 8 {
		if tableOffset+8 > len(loader) {
			return nil, fmt.Errorf(
				"PELOCKnt encrypted-section table is unterminated",
			)
		}
		rva := binary.LittleEndian.Uint32(loader[tableOffset:])
		if rva == 0 {
			break
		}
		declaredSize := binary.LittleEndian.Uint32(
			loader[tableOffset+4:],
		)
		section := sectionByRVA(image.file.Sections, rva)
		if section == nil || section == loaderSection {
			return nil, fmt.Errorf(
				"PELOCKnt table references unknown section RVA %#x",
				rva,
			)
		}
		if declaredSize != section.Size {
			return nil, fmt.Errorf(
				"PELOCKnt table declares section RVA %#x size %#x; "+
					"PE header says %#x",
				rva,
				declaredSize,
				section.Size,
			)
		}
		encryptedData, err := image.rawSectionData(section)
		if err != nil {
			return nil, err
		}
		decryptedData, err := decryptPELockSection(
			encryptedData,
			rva,
			sectionKey,
			skipRanges,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"decrypt section RVA %#x: %w",
				rva,
				err,
			)
		}
		sections = append(sections, decryptedSection{
			section: section,
			data:    decryptedData,
		})
	}
	if len(sections) == 0 {
		return nil, fmt.Errorf(
			"PELOCKnt encrypted-section table is empty",
		)
	}
	return sections, nil
}

func decryptPELockLoader(loader []byte) error {
	if len(loader) < peLockLoaderMinimumSize {
		return fmt.Errorf(
			"PELOCKnt loader has %#x bytes; need at least %#x",
			len(loader),
			peLockLoaderMinimumSize,
		)
	}

	firstKey := loader[0x6f]
	for index := 0; index < 0x260b; index++ {
		loader[0x9c+index] ^= firstKey ^ byte(0x260b-index)
	}

	state := loader[0xf9]
	for index := 0; index < 0x2583; index++ {
		loader[0x124+index] ^= state
		state ^= byte(0x2583 - index)
	}

	state = loader[0x207]
	for index := 0; index < 0x2475; index++ {
		loader[0x232+index] ^= state
		state ^= byte(0x2475 - index)
	}

	state = loader[0x296]
	for index := 0; index < 0x23cd; index++ {
		remaining := 0x23cd - index
		value := loader[0x2da+index] ^ state
		loader[0x2da+index] = bits.RotateLeft8(value, -(remaining & 7))
		state ^= byte(remaining)
	}
	return nil
}

func decryptPELockSection(
	encryptedData []byte,
	sectionRVA uint32,
	sectionKey uint32,
	skipRanges []peLockSkipRange,
) ([]byte, error) {
	if len(encryptedData)%4 != 0 {
		return nil, fmt.Errorf(
			"raw size %#x is not divisible by four",
			len(encryptedData),
		)
	}
	decryptedData := append([]byte(nil), encryptedData...)
	remaining := uint32(len(decryptedData) / 4)
	for offset := uint32(0); remaining != 0; offset, remaining = offset+4, remaining-1 {
		address := sectionRVA + offset
		if isSkippedPELockAddress(address, skipRanges) {
			continue
		}
		value := binary.LittleEndian.Uint32(decryptedData[offset:])
		value = reverseLowWordBytes(value)
		value ^= remaining
		if remaining&4 != 0 {
			value ^= remaining * peLockSectionMultiplier
		}
		value = bits.RotateLeft32(value, int(remaining))
		value ^= sectionKey
		value = reverseLowWordBytes(value)
		binary.LittleEndian.PutUint32(decryptedData[offset:], value)
	}
	return decryptedData, nil
}

func sectionByRVA(sections []*pe.Section, rva uint32) *pe.Section {
	for _, section := range sections {
		if section.VirtualAddress == rva {
			return section
		}
	}
	return nil
}

func isSkippedPELockAddress(
	address uint32, ranges []peLockSkipRange,
) bool {
	for _, candidate := range ranges {
		if address >= candidate.start && address < candidate.end {
			return true
		}
	}
	return false
}

func reverseLowWordBytes(value uint32) uint32 {
	return value&0xffff0000 | uint32(bits.ReverseBytes16(uint16(value)))
}
