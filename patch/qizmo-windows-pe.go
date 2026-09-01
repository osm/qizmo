package main

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
)

// Types

type windowsPERebuildPatch struct{}

// Constants and static PE metadata

const (
	peSectionCode              = uint32(0x00000020)
	peSectionInitializedData   = uint32(0x00000040)
	peSectionExecute           = uint32(0x20000000)
	peSectionRead              = uint32(0x40000000)
	peSectionWrite             = uint32(0x80000000)
	pe32DataDirectoryOffset    = 96
	peSectionHeaderSize        = 40
	peImportDirectoryIndex     = 1
	peRelocationDirectoryIndex = 5
)

var originalPESectionNames = [...]string{".text", ".rdata", ".data", ".idata"}

var originalPESectionCharacteristics = [...]uint32{
	peSectionCode | peSectionExecute | peSectionRead,
	peSectionInitializedData | peSectionRead,
	peSectionInitializedData | peSectionRead | peSectionWrite,
	peSectionInitializedData | peSectionRead | peSectionWrite,
}

// Patch stage

func (windowsPERebuildPatch) String() string {
	return "rebuild: rebuild the original PE32 image"
}

func (windowsPERebuildPatch) apply(context *patchContext) error {
	state, err := windowsState(context)
	if err != nil {
		return err
	}
	if err := state.rebuildPE(); err != nil {
		return err
	}
	context.output = state.output
	return nil
}

func (state *windowsUnlockState) rebuildPE() error {
	if state.protected == nil || state.peLock == nil || state.compression == nil {
		return fmt.Errorf("required Qizmo compression layer has not been decoded")
	}

	output, err := rebuildOriginalPE(
		state.protected,
		state.peLock,
		state.compression,
	)
	if err != nil {
		return err
	}
	if outputDigest := digest(output); outputDigest != windowsRebuiltSHA256 {
		return fmt.Errorf(
			"rebuilt sha256 is %s, want %s",
			outputDigest,
			windowsRebuiltSHA256,
		)
	}
	state.output = output
	return nil
}

// PE32 reconstruction

func rebuildOriginalPE(
	protected *protectedPE,
	peLock *peLockPayload,
	compression *qizmoCompressionPayload,
) ([]byte, error) {
	optional, err := validateOriginalPEInput(protected, peLock, compression)
	if err != nil {
		return nil, err
	}
	peOffset, optionalOffset, sectionTableOffset, err := locatePEHeaders(
		protected.input,
	)
	if err != nil {
		return nil, err
	}
	if sectionTableOffset+
		len(protected.file.Sections)*peSectionHeaderSize >
		len(protected.input) {
		return nil, fmt.Errorf(
			"PE section table extends beyond input headers",
		)
	}

	rawSizes, outputSize, err := originalPESectionSizes(
		optional,
		peLock,
		compression,
	)
	if err != nil {
		return nil, err
	}
	rebuilt := make([]byte, outputSize)
	copy(rebuilt, protected.input[:optional.SizeOfHeaders])
	writeOriginalPEHeaders(
		rebuilt,
		peOffset,
		optionalOffset,
		optional,
		peLock,
		compression,
	)
	writeOriginalPESections(
		rebuilt,
		sectionTableOffset,
		optional.SizeOfHeaders,
		rawSizes,
		peLock,
		compression,
	)
	clearUnusedPESectionHeaders(
		rebuilt,
		sectionTableOffset,
		len(protected.file.Sections),
	)
	if err := validateOriginalPE(rebuilt, compression.entryPointRVA); err != nil {
		return nil, err
	}
	return rebuilt, nil
}

func validateOriginalPEInput(
	protected *protectedPE,
	peLock *peLockPayload,
	compression *qizmoCompressionPayload,
) (*pe.OptionalHeader32, error) {
	const originalSectionCount = len(originalPESectionNames)
	if len(peLock.sections) != originalSectionCount+1 {
		return nil, fmt.Errorf(
			"compressed Qizmo image has %d sections; "+
				"expected %d original sections "+
				"plus one stub",
			len(peLock.sections),
			originalSectionCount,
		)
	}
	optional, ok := protected.file.OptionalHeader.(*pe.OptionalHeader32)
	if !ok {
		return nil, fmt.Errorf("PE32 optional header is unavailable")
	}
	if !isPowerOfTwo(optional.FileAlignment) {
		return nil, fmt.Errorf(
			"invalid PE file alignment %#x",
			optional.FileAlignment,
		)
	}
	if !isPowerOfTwo(optional.SectionAlignment) {
		return nil, fmt.Errorf(
			"invalid PE section alignment %#x",
			optional.SectionAlignment,
		)
	}
	if optional.SizeOfHeaders > uint32(len(protected.input)) {
		return nil, fmt.Errorf(
			"PE headers size %#x exceeds input size %#x",
			optional.SizeOfHeaders,
			len(protected.input),
		)
	}
	expandedText, found := compression.dataForSection(0, nil)
	if !found {
		return nil, fmt.Errorf(
			"compression payload does not contain the first section",
		)
	}
	if optional.SizeOfCode > uint32(len(expandedText)) {
		return nil, fmt.Errorf(
			"PE SizeOfCode %#x exceeds expanded first section size %#x",
			optional.SizeOfCode,
			len(expandedText),
		)
	}
	for _, value := range expandedText[optional.SizeOfCode:] {
		if value != 0 {
			return nil, fmt.Errorf(
				"expanded first-section tail beyond SizeOfCode " +
					"contains initialized data",
			)
		}
	}
	return optional, nil
}

func isPowerOfTwo(value uint32) bool {
	return value != 0 && value&(value-1) == 0
}

func originalPESectionSizes(
	optional *pe.OptionalHeader32,
	peLock *peLockPayload,
	compression *qizmoCompressionPayload,
) ([len(originalPESectionNames)]uint32, uint32, error) {
	var rawSizes [len(originalPESectionNames)]uint32
	for index := range rawSizes {
		sectionData, expanded := compression.dataForSection(
			index,
			peLock.sections[index].data,
		)
		if expanded {
			rawSizes[index] = initializedSectionSize(
				sectionData,
				optional.FileAlignment,
			)
		} else {
			rawSizes[index] = alignUp(
				uint32(len(sectionData)),
				optional.FileAlignment,
			)
		}
	}
	if rawSizes[0] != optional.SizeOfCode {
		return rawSizes, 0, fmt.Errorf(
			"expanded .text initialized size %#x does not match "+
				"PE SizeOfCode %#x",
			rawSizes[0],
			optional.SizeOfCode,
		)
	}

	outputSize := optional.SizeOfHeaders
	for _, size := range rawSizes {
		if size > ^uint32(0)-outputSize {
			return rawSizes, 0, fmt.Errorf(
				"rebuilt PE file size overflows 32 bits",
			)
		}
		outputSize += size
	}
	return rawSizes, outputSize, nil
}

func writeOriginalPEHeaders(
	rebuilt []byte,
	peOffset int,
	optionalOffset int,
	optional *pe.OptionalHeader32,
	peLock *peLockPayload,
	compression *qizmoCompressionPayload,
) {
	const originalSectionCount = len(originalPESectionNames)
	fileHeaderOffset := peOffset + 4
	binary.LittleEndian.PutUint16(
		rebuilt[fileHeaderOffset+2:],
		uint16(originalSectionCount),
	)
	binary.LittleEndian.PutUint32(
		rebuilt[optionalOffset+16:],
		compression.entryPointRVA,
	)
	last := peLock.sections[originalSectionCount-1].section
	sizeOfImage := alignUp(
		last.VirtualAddress+last.VirtualSize,
		optional.SectionAlignment,
	)
	binary.LittleEndian.PutUint32(rebuilt[optionalOffset+56:], sizeOfImage)
	binary.LittleEndian.PutUint32(rebuilt[optionalOffset+64:], 0)
	writePEDataDirectory(
		rebuilt,
		optionalOffset,
		peImportDirectoryIndex,
		peLock.importRVA,
		peLock.importSize,
	)
	writePEDataDirectory(
		rebuilt,
		optionalOffset,
		peRelocationDirectoryIndex,
		peLock.relocationRVA,
		peLock.relocationSize,
	)
}

func writeOriginalPESections(
	rebuilt []byte,
	sectionTableOffset int,
	rawOffset uint32,
	rawSizes [len(originalPESectionNames)]uint32,
	peLock *peLockPayload,
	compression *qizmoCompressionPayload,
) {
	for index := range originalPESectionNames {
		headerOffset := sectionTableOffset + index*peSectionHeaderSize
		zeroBytes(rebuilt[headerOffset : headerOffset+8])
		copy(
			rebuilt[headerOffset:headerOffset+8],
			originalPESectionNames[index],
		)
		binary.LittleEndian.PutUint32(
			rebuilt[headerOffset+16:],
			rawSizes[index],
		)
		binary.LittleEndian.PutUint32(
			rebuilt[headerOffset+20:],
			rawOffset,
		)
		zeroBytes(rebuilt[headerOffset+24 : headerOffset+36])
		binary.LittleEndian.PutUint32(
			rebuilt[headerOffset+36:],
			originalPESectionCharacteristics[index],
		)

		sectionData, _ := compression.dataForSection(
			index,
			peLock.sections[index].data,
		)
		copy(rebuilt[rawOffset:rawOffset+rawSizes[index]], sectionData)
		rawOffset += rawSizes[index]
	}
}

func clearUnusedPESectionHeaders(
	rebuilt []byte,
	sectionTableOffset int,
	sectionCount int,
) {
	for index := len(originalPESectionNames); index < sectionCount; index++ {
		headerOffset := sectionTableOffset + index*peSectionHeaderSize
		zeroBytes(rebuilt[headerOffset : headerOffset+peSectionHeaderSize])
	}
}

func zeroBytes(data []byte) {
	for index := range data {
		data[index] = 0
	}
}

func validateOriginalPE(rebuilt []byte, entryPointRVA uint32) error {
	file, err := pe.NewFile(bytes.NewReader(rebuilt))
	if err != nil {
		return fmt.Errorf("validate rebuilt PE: %w", err)
	}
	defer file.Close()
	if len(file.Sections) != len(originalPESectionNames) {
		return fmt.Errorf(
			"validate rebuilt PE: parsed %d sections",
			len(file.Sections),
		)
	}
	optional, ok := file.OptionalHeader.(*pe.OptionalHeader32)
	if !ok || optional.AddressOfEntryPoint != entryPointRVA {
		return fmt.Errorf(
			"validate rebuilt PE: entry point was not preserved",
		)
	}
	imports, err := file.ImportedSymbols()
	if err != nil {
		return fmt.Errorf("validate rebuilt PE imports: %w", err)
	}
	if len(imports) == 0 {
		return fmt.Errorf(
			"validate rebuilt PE: import table is empty",
		)
	}
	return nil
}

func locatePEHeaders(
	fileData []byte,
) (
	peHeaderOffset int,
	optionalHeaderOffset int,
	sectionTableOffset int,
	err error,
) {
	if len(fileData) < 0x40 || string(fileData[:2]) != "MZ" {
		return 0, 0, 0, fmt.Errorf("invalid DOS header")
	}
	rawPEOffset := uint64(binary.LittleEndian.Uint32(fileData[0x3c:]))
	peHeaderEnd := rawPEOffset + 24
	if peHeaderEnd > uint64(len(fileData)) ||
		string(fileData[rawPEOffset:rawPEOffset+4]) != "PE\x00\x00" {
		return 0, 0, 0, fmt.Errorf(
			"invalid PE header offset %#x",
			rawPEOffset,
		)
	}
	peHeaderOffset = int(rawPEOffset)
	optionalHeaderOffset = peHeaderOffset + 24
	optionalHeaderSize := int(binary.LittleEndian.Uint16(
		fileData[peHeaderOffset+20:],
	))
	sectionTableOffset = optionalHeaderOffset + optionalHeaderSize
	if optionalHeaderOffset+optionalHeaderSize > len(fileData) {
		return 0, 0, 0, fmt.Errorf("PE optional header extends beyond input")
	}
	if optionalHeaderSize < pe32DataDirectoryOffset+16*8 {
		return 0, 0, 0, fmt.Errorf(
			"PE32 optional header is too small (%#x bytes)",
			optionalHeaderSize,
		)
	}
	return peHeaderOffset, optionalHeaderOffset, sectionTableOffset, nil
}

func writePEDataDirectory(
	data []byte,
	optionalHeaderOffset int,
	directoryIndex int,
	rva uint32,
	size uint32,
) {
	offset := optionalHeaderOffset +
		pe32DataDirectoryOffset +
		directoryIndex*8
	binary.LittleEndian.PutUint32(data[offset:], rva)
	binary.LittleEndian.PutUint32(data[offset+4:], size)
}

func alignUp(value, alignment uint32) uint32 {
	return (value + alignment - 1) &^ (alignment - 1)
}

func initializedSectionSize(sectionData []byte, alignment uint32) uint32 {
	initializedSize := len(sectionData)
	for initializedSize > 0 && sectionData[initializedSize-1] == 0 {
		initializedSize--
	}
	return alignUp(uint32(initializedSize), alignment)
}
