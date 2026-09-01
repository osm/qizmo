package main

import (
	"encoding/binary"
	"fmt"
)

// Types

type windowsQizmoCompressionPatch struct{}

type expandedSection struct {
	sectionIndex int
	data         []byte
}

type qizmoCompressionPayload struct {
	sections      []expandedSection
	entryPointRVA uint32
}

type qizmoBitReader struct {
	input         []byte
	offset        int
	word          uint32
	bitsRemaining int
}

type qizmoCompressionDecoder struct {
	reader       *qizmoBitReader
	output       []byte
	expandedSize int
}

// Constants

const (
	qizmoMetadataOffset         = 0x295
	qizmoDescriptorStep         = 0x11
	qizmoTargetDeltaOffset      = 0x2a1
	qizmoExpandedSizeOffset     = 0x2a5
	qizmoStreamDwordCountOffset = 0x2a9
	qizmoStreamSizeOffset       = 0x2ad
	qizmoHasNextOffset          = 0x2b1
)

// Patch stage

func (windowsQizmoCompressionPatch) String() string {
	return "compression: decode Qizmo's compression layer"
}

func (windowsQizmoCompressionPatch) apply(context *patchContext) error {
	state, err := windowsState(context)
	if err != nil {
		return err
	}
	return state.decodeQizmoCompression()
}

func (state *windowsUnlockState) decodeQizmoCompression() error {
	if state.protected == nil || state.peLock == nil {
		return fmt.Errorf("required PELOCKnt layer has not been decoded")
	}

	compression, err := unpackQizmoCompression(
		state.protected,
		state.peLock.sections,
	)
	if err != nil {
		return err
	}
	state.compression = compression
	return nil
}

// Qizmo compression layer

// unpackQizmoCompression removes the small compression layer inside PELOCKnt. The
// metadata layout and decoder are a bounds-checked translation of Qizmo 2.91's
// position-independent x86 unpacking stub.
func unpackQizmoCompression(
	protected *protectedPE,
	sections []decryptedSection,
) (*qizmoCompressionPayload, error) {
	if len(sections) < 2 {
		return nil, fmt.Errorf(
			"compressed Qizmo image has only %d section(s)",
			len(sections),
		)
	}
	packedText := sections[0]
	stub := sections[len(sections)-1]
	entryPoint, err := qizmoEntryPoint(protected, packedText, stub)
	if err != nil {
		return nil, err
	}

	compression := &qizmoCompressionPayload{entryPointRVA: entryPoint}
	seen := make(map[int]bool)
	for descriptor := 0; ; descriptor++ {
		expanded, hasNext, err := unpackQizmoDescriptor(
			stub,
			sections,
			descriptor,
			seen,
		)
		if err != nil {
			return nil, err
		}
		compression.sections = append(compression.sections, expanded)
		if !hasNext {
			break
		}
	}
	if len(compression.sections) == 0 || compression.sections[0].sectionIndex != 0 {
		return nil, fmt.Errorf(
			"compression descriptors do not begin with the first section",
		)
	}
	return compression, nil
}

func qizmoEntryPoint(
	protected *protectedPE,
	packedText decryptedSection,
	stub decryptedSection,
) (uint32, error) {
	if len(stub.data) < qizmoHasNextOffset+1 {
		return 0, fmt.Errorf(
			"compression stub has %#x bytes; first descriptor ends at %#x",
			len(stub.data),
			qizmoHasNextOffset+1,
		)
	}
	metadata := stub.data[qizmoMetadataOffset:]
	entryDelta := int32(binary.LittleEndian.Uint32(metadata[0:]))
	preferredImageBase := binary.LittleEndian.Uint32(metadata[4:])
	preferredStubVA := binary.LittleEndian.Uint32(metadata[8:])
	if preferredImageBase != protected.imageBase {
		return 0, fmt.Errorf(
			"compression stub image base %#x does not match PE header %#x",
			preferredImageBase,
			protected.imageBase,
		)
	}
	stubVA := protected.imageBase + stub.section.VirtualAddress
	if preferredStubVA != stubVA {
		return 0, fmt.Errorf(
			"compression stub VA %#x does not match section VA %#x",
			preferredStubVA,
			stubVA,
		)
	}
	entryPoint := uint32(
		int64(stub.section.VirtualAddress) +
			int64(qizmoMetadataOffset+4) +
			int64(entryDelta),
	)
	textEnd := uint64(packedText.section.VirtualAddress) +
		uint64(packedText.section.VirtualSize)
	if entryPoint < packedText.section.VirtualAddress ||
		uint64(entryPoint) >= textEnd {
		return 0, fmt.Errorf(
			"recovered entry-point RVA %#x is outside the first section",
			entryPoint,
		)
	}
	return entryPoint, nil
}

func unpackQizmoDescriptor(
	stub decryptedSection,
	sections []decryptedSection,
	descriptor int,
	seen map[int]bool,
) (expandedSection, bool, error) {
	offset := descriptor * qizmoDescriptorStep
	if qizmoHasNextOffset+offset >= len(stub.data) {
		return expandedSection{}, false, fmt.Errorf(
			"compression descriptor %d extends beyond the stub",
			descriptor,
		)
	}
	stubDelta := binary.LittleEndian.Uint32(
		stub.data[qizmoTargetDeltaOffset+offset:],
	)
	if stubDelta > stub.section.VirtualAddress {
		return expandedSection{}, false, fmt.Errorf(
			"compression descriptor %d has invalid stub delta %#x",
			descriptor,
			stubDelta,
		)
	}
	targetRVA := stub.section.VirtualAddress - stubDelta
	sectionIndex := qizmoSectionIndex(sections, targetRVA)
	if sectionIndex < 0 {
		return expandedSection{}, false, fmt.Errorf(
			"compression descriptor %d targets unknown section RVA %#x",
			descriptor,
			targetRVA,
		)
	}
	if seen[sectionIndex] {
		return expandedSection{}, false, fmt.Errorf(
			"compression descriptor %d repeats section %d",
			descriptor,
			sectionIndex,
		)
	}
	seen[sectionIndex] = true

	expandedSize := binary.LittleEndian.Uint32(
		stub.data[qizmoExpandedSizeOffset+offset:],
	) + 4
	streamDwords := binary.LittleEndian.Uint32(
		stub.data[qizmoStreamDwordCountOffset+offset:],
	)
	streamSize := binary.LittleEndian.Uint32(
		stub.data[qizmoStreamSizeOffset+offset:],
	) + 4
	target := sections[sectionIndex]
	if expandedSize != target.section.VirtualSize {
		return expandedSection{}, false, fmt.Errorf(
			"compression descriptor %d expanded size %#x; section size is %#x",
			descriptor,
			expandedSize,
			target.section.VirtualSize,
		)
	}
	if streamDwords > ^uint32(0)/4 || streamDwords*4 != streamSize {
		return expandedSection{}, false, fmt.Errorf(
			"compression descriptor %d stream size %#x; move count is %#x",
			descriptor,
			streamSize,
			streamDwords,
		)
	}
	if streamSize > uint32(len(target.data)) {
		return expandedSection{}, false, fmt.Errorf(
			"compression descriptor %d stream size %#x exceeds section size %#x",
			descriptor,
			streamSize,
			len(target.data),
		)
	}
	expandedData, err := decompressQizmoSection(
		target.data[:streamSize],
		int(expandedSize),
	)
	if err != nil {
		return expandedSection{}, false, fmt.Errorf(
			"decompress Qizmo section RVA %#x: %w",
			targetRVA,
			err,
		)
	}
	return expandedSection{
		sectionIndex: sectionIndex,
		data:         expandedData,
	}, stub.data[qizmoHasNextOffset+offset] != 0, nil
}

func qizmoSectionIndex(
	sections []decryptedSection,
	targetRVA uint32,
) int {
	for index := range sections[:len(sections)-1] {
		if sections[index].section.VirtualAddress == targetRVA {
			return index
		}
	}
	return -1
}

func (compression *qizmoCompressionPayload) dataForSection(
	index int, fallbackData []byte,
) ([]byte, bool) {
	for _, section := range compression.sections {
		if section.sectionIndex == index {
			return section.data, true
		}
	}
	return fallbackData, false
}

func newQizmoBitReader(input []byte) (*qizmoBitReader, error) {
	reader := &qizmoBitReader{input: input}
	if err := reader.refill(); err != nil {
		return nil, err
	}
	return reader, nil
}

func (reader *qizmoBitReader) refill() error {
	if reader.offset+4 > len(reader.input) {
		return fmt.Errorf(
			"compressed bitstream ends at %#x",
			reader.offset,
		)
	}
	reader.word = binary.LittleEndian.Uint32(
		reader.input[reader.offset:],
	)
	reader.offset += 4
	reader.bitsRemaining = 32
	return nil
}

func (reader *qizmoBitReader) readBit() (uint32, error) {
	value := reader.word >> 31
	reader.word <<= 1
	reader.bitsRemaining--
	if reader.bitsRemaining == 0 {
		if err := reader.refill(); err != nil {
			return 0, err
		}
	}
	return value, nil
}

func (reader *qizmoBitReader) readBits(count uint8) (uint16, error) {
	var value uint16
	for index := uint8(0); index < count; index++ {
		bit, err := reader.readBit()
		if err != nil {
			return 0, err
		}
		value = value<<1 | uint16(bit)
	}
	return value, nil
}

func (reader *qizmoBitReader) readLiteral() (byte, error) {
	if reader.offset >= len(reader.input) {
		return 0, fmt.Errorf(
			"compressed literals end at %#x",
			reader.offset,
		)
	}
	value := reader.input[reader.offset]
	reader.offset++
	return value, nil
}

func (decoder *qizmoCompressionDecoder) appendMatch(distance, length uint16) error {
	if distance == 0 || int(distance) > len(decoder.output) {
		return fmt.Errorf(
			"invalid distance %#x at output %#x",
			distance,
			len(decoder.output),
		)
	}
	if int(length) > decoder.expandedSize-len(decoder.output) {
		return fmt.Errorf(
			"match exceeds expected output size %#x",
			decoder.expandedSize,
		)
	}
	for index := uint16(0); index < length; index++ {
		decoder.output = append(
			decoder.output,
			decoder.output[len(decoder.output)-int(distance)],
		)
	}
	return nil
}

func (decoder *qizmoCompressionDecoder) decodeShortMatch() (endOfStream bool, err error) {
	selector, err := decoder.reader.readBits(2)
	if err != nil {
		return false, err
	}
	bitCount := uint8(selector + 5)
	distanceBase := uint16(1)
	if selector > 1 {
		bitCount++
		distanceBase = distanceBase<<bitCount - 0x9f
	} else {
		distanceBase <<= bitCount
		distanceBase = distanceBase&0xff00 | uint16(byte(distanceBase)-0x1f)
	}
	distanceBits, err := decoder.reader.readBits(bitCount)
	if err != nil {
		return false, err
	}
	if distanceBits == 0x1ff {
		return true, nil
	}
	return false, decoder.appendMatch(distanceBits+distanceBase, 2)
}

func (decoder *qizmoCompressionDecoder) decodeDistance() (uint16, error) {
	code, err := decoder.reader.readBits(3)
	if err != nil {
		return 0, err
	}
	switch {
	case code < 3:
		code += 5
	case code == 3:
		bit, err := decoder.reader.readBit()
		if err != nil {
			return 0, err
		}
		code += 5 + uint16(bit)
	case code == 4:
		bit, err := decoder.reader.readBit()
		if err != nil {
			return 0, err
		}
		code += 6 + uint16(bit)
	default:
		code += 7
	}

	switch code {
	case 13:
		value, err := decoder.reader.readBits(14)
		return value + 0x1fe1, err
	case 14:
		value, err := decoder.reader.readBits(15)
		return value + 0x5fe1, err
	default:
		base := uint16(1)<<uint8(code) - 0x1f
		value, err := decoder.reader.readBits(uint8(code))
		return value + base, err
	}
}

func (decoder *qizmoCompressionDecoder) decodeMatchLength(tag uint16) (uint16, error) {
	if tag >= 1 {
		return tag + 2, nil
	}

	first, err := decoder.reader.readBit()
	if err != nil {
		return 0, err
	}
	if first == 0 {
		second, err := decoder.reader.readBit()
		return 5 + uint16(second), err
	}

	value, err := decoder.reader.readBits(3)
	if err != nil || value != 0 {
		return value + 6, err
	}
	value, err = decoder.reader.readBits(4)
	if err != nil || value != 0 {
		return value + 13, err
	}

	base := uint16(13)
	for count := uint8(4); ; count++ {
		if count == 7 {
			return decoder.reader.readBits(14)
		}
		base = (base+2)*2 - 1
		bit, err := decoder.reader.readBit()
		if err != nil {
			return 0, err
		}
		if bit != 0 {
			value, err := decoder.reader.readBits(count + 1)
			return value + base, err
		}
	}
}

func decompressQizmoSection(
	compressedData []byte, expandedSize int,
) ([]byte, error) {
	if expandedSize < 0 {
		return nil, fmt.Errorf("negative expanded size %d", expandedSize)
	}
	reader, err := newQizmoBitReader(compressedData)
	if err != nil {
		return nil, err
	}
	decoder := &qizmoCompressionDecoder{
		reader:       reader,
		output:       make([]byte, 0, expandedSize),
		expandedSize: expandedSize,
	}

	for {
		isMatch, err := reader.readBit()
		if err != nil {
			return nil, err
		}
		if isMatch == 0 {
			literal, err := reader.readLiteral()
			if err != nil {
				return nil, err
			}
			if len(decoder.output) == expandedSize {
				return nil, fmt.Errorf("literal exceeds expected output size %#x", expandedSize)
			}
			decoder.output = append(decoder.output, literal)
			continue
		}

		tag, err := reader.readBits(2)
		if err != nil {
			return nil, err
		}
		if tag == 3 {
			endOfStream, err := decoder.decodeShortMatch()
			if err != nil {
				return nil, err
			}
			if endOfStream {
				break
			}
			continue
		}

		distance, err := decoder.decodeDistance()
		if err != nil {
			return nil, err
		}
		length, err := decoder.decodeMatchLength(tag)
		if err != nil {
			return nil, err
		}
		if err := decoder.appendMatch(distance, length); err != nil {
			return nil, err
		}
	}

	padding := make([]byte, expandedSize-len(decoder.output))
	return append(decoder.output, padding...), nil
}
