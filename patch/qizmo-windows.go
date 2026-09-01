package main

// Windows Qizmo 2.91 is a valid PE32 file wrapped in two protection layers.
// Its PE header and section table remain readable, but the entry point targets
// a PELOCKnt v2.04 loader in the last section instead of Qizmo's original code.
// The four original sections are transformed, and a second Qizmo-specific
// compression stub is stored immediately inside the PELOCKnt layer.
//
// Unlocking is entirely static and deterministic; there is no password to
// discover and no protected code is executed. The PELOCKnt loader contains all
// material needed to reverse the outer layer. Removing its four nested byte
// transforms exposes the section key, encrypted-section table, address ranges
// excluded from transformation, import directory, and relocation directory.
// Each listed section is then restored with PELOCKnt's inverse DWORD transform.
//
// The resulting image still contains Qizmo's compression layer. Its stub
// describes the target sections, compressed stream sizes, expanded sizes, and
// original entry-point delta. A bounds-checked Go decoder expands its LZ-style
// literal and back-reference streams. The final rebuild discards both stubs,
// restores the original .text, .rdata, .data, and .idata sections, repairs the
// entry point and PE directories, and parses the result again for validation.
//
// The caller accepts only the exact protected Qizmo 2.91 SHA-256 and verifies
// the rebuilt SHA-256 before applying any compatibility patches. This is a
// self-contained patcher-specific implementation; the independent
// multi-version tool under cmd/qizmo-unpack is not imported or linked here.

import (
	"bytes"
	"fmt"
)

// Types

type windowsUnlockState struct {
	input       []byte
	protected   *protectedPE
	peLock      *peLockPayload
	compression *qizmoCompressionPayload
	output      []byte
}

// Constants and static PE metadata

const (
	windowsProtectedSHA256 = "d06684ac8bfe7abaac978671da26ad2d" +
		"fae7e6679731fccd0a534baba5e9b020"
	windowsRebuiltSHA256 = "3fea19970254d739974743301644d990b" +
		"95e8873ed5c31d43afa406546ae5423"
	windowsPatchedWithoutBannerSHA256 = "34a4b2d05b62c6c9bc237d55b6f32dba" +
		"369ab0c5438b3bcbc7fab5bbc1fb5bad"
	windowsPatchedSHA256 = "b8652b0e80d9a5c00c64cbc3fa693c2c" +
		"666dcc09feeb001a0d4759b037fe4035"

	windowsStructuralPatchCount    = 3
	windowsCompatibilityPatchStart = windowsStructuralPatchCount
	windowsBannerPatchIndex        = windowsCompatibilityPatchStart + 1
)

// windowsPatches is the complete Windows workflow in execution order. Every
// entry implements patch, whether it transforms the PE structure or replaces
// validated bytes in the rebuilt image.
var windowsPatches = []patch{
	windowsPELockPatch{},
	windowsQizmoCompressionPatch{},
	windowsPERebuildPatch{},
	windowsIntegrityPatch,
	windowsBannerPatch,
	windowsUserinfoPatch,
}

// patchWindows recognizes the supported protected, rebuilt, and patched
// Windows Qizmo 2.91 images. Protected input is rebuilt in memory before the
// compatibility patches are applied.
func patchWindows(
	input []byte,
	inputDigest string,
) (*patchResult, bool, error) {
	switch inputDigest {
	case windowsPatchedSHA256:
		return &patchResult{
			Output:   bytes.Clone(input),
			Platform: "windows",
		}, true, nil
	case windowsPatchedWithoutBannerSHA256:
		output, steps, err := applyPatchSequence(
			input,
			windowsPatches[windowsBannerPatchIndex:windowsBannerPatchIndex+1],
			nil,
			windowsPatchedSHA256,
		)
		if err != nil {
			return nil, true, err
		}
		return &patchResult{
			Output:   output,
			Changed:  true,
			Platform: "windows",
			Steps:    steps,
		}, true, nil
	case windowsRebuiltSHA256:
		output, steps, err := applyPatchSequence(
			input,
			windowsPatches[windowsCompatibilityPatchStart:],
			nil,
			windowsPatchedSHA256,
		)
		if err != nil {
			return nil, true, err
		}
		return &patchResult{
			Output:   output,
			Changed:  true,
			Platform: "windows",
			Steps:    steps,
		}, true, nil
	case windowsProtectedSHA256:
		state := &windowsUnlockState{input: input}
		defer state.close()

		output, steps, err := applyPatchSequence(
			input,
			windowsPatches,
			state,
			windowsPatchedSHA256,
		)
		if err != nil {
			return nil, true, err
		}
		return &patchResult{
			Output:   output,
			Changed:  true,
			Platform: "windows",
			Steps:    steps,
		}, true, nil
	default:
		return nil, false, nil
	}
}

func windowsState(context *patchContext) (*windowsUnlockState, error) {
	state, ok := context.state.(*windowsUnlockState)
	if !ok {
		return nil, fmt.Errorf(
			"required Windows unlocking state is unavailable",
		)
	}
	return state, nil
}

func (state *windowsUnlockState) close() {
	if state.protected != nil {
		_ = state.protected.file.Close()
	}
}

// Windows patches

// The rebuilt Windows PE contains the same source-level integrity mechanism as
// Linux at different addresses. The first two replacements retire the scanner
// and trap callback. The third forces the existing final guard onto its normal
// continuation. The structural patches above remove PELOCKnt and the Qizmo
// compressor before these offsets are used.
var windowsIntegrityPatch = bytePatch{
	Name:        "integrity",
	Description: "remove the integrity check",
	Replacements: []replacement{
		{
			Name:   "skip executable scanner",
			Offset: 0x32277, // VA 0x01032e77
			Before: []byte{0xe8, 0x84, 0xaa, 0xff, 0xff},
			After:  []byte{0x90, 0x90, 0x90, 0x90, 0x90},
		},
		{
			Name:   "skip integrity callback",
			Offset: 0x32de6, // VA 0x010339e6
			Before: []byte{0xff, 0x15, 0xc0, 0x96, 0x07, 0x01},
			After:  []byte{0x90, 0x90, 0x90, 0x90, 0x90, 0x90},
		},
		{
			Name:   "force integrity success branch",
			Offset: 0x32ee5, // VA 0x01033ae5
			Before: []byte{0x75, 0x18},
			After:  []byte{0xeb, 0x18},
		},
	},
}

// As on Linux, the retired integrity mechanism provides enough executable and
// writable space for the banner extension. The original banner remains the
// format string; two same-size placeholders insert the attribution after the
// copyright line and append the repository URL after Qizmo's historical URL.
var windowsBannerPatch = bytePatch{
	Name:        "banner",
	Description: "add the compatibility attribution and repository URL",
	Replacements: []replacement{
		{
			Name:   "attribution storage",
			Offset: 0x78050, // VA 0x01079650
			Before: []byte{
				0x0a, 0x5e, 0xbc, 0xd1, 0xdc, 0x93, 0x89, 0xdc,
				0x93, 0x99, 0xe8, 0xe4, 0xe7, 0x92, 0x8c, 0xcd,
				0xd4, 0xe7, 0x94, 0x97, 0xd8, 0xd3, 0xe0, 0xd7,
				0xd7, 0xd5, 0x95, 0x38, 0x5c, 0xb7, 0xd2, 0xdc,
				0xe5, 0xdb, 0x85, 0x8f, 0xdd, 0xd3, 0x85, 0x8d,
				0xdc, 0xe1, 0xd7, 0x85, 0x90, 0xe2, 0xe1, 0xe3,
				0xd9,
			},
			After: []byte(
				"\nCompatibility fixes by " +
					"Oscar Linderholm, 2026\nF\x00",
			),
		},
		{
			Name:   "repository URL storage",
			Offset: 0x78081, // VA 0x01079681
			Before: []byte{
				0xc8, 0xd7, 0xdd, 0xd8, 0xdd, 0x8e, 0x81, 0xcf,
				0xd2, 0x84, 0x99, 0xe8, 0xe4, 0x95, 0x83, 0xc4,
				0xcf, 0x8e, 0x8b, 0xd4, 0xdc, 0xe6, 0x7d, 0x6b,
				0xcd, 0xd8, 0x8c, 0x84, 0xc5, 0xd5, 0xd5, 0x81,
				0x8f, 0xdd,
			},
			After: []byte(
				" | https://github.com/osm/qizmo\n\n\x00",
			),
		},
		{
			Name:   "banner format placeholder",
			Offset: 0x78d8b,
			Before: []byte("\nF"),
			After:  []byte("%s"),
		},
		{
			Name:   "repository URL format placeholder",
			Offset: 0x78ddf,
			Before: []byte("\n\n"),
			After:  []byte("%s"),
		},
		{
			Name:   "banner printf trampoline",
			Offset: 0x31d60, // VA 0x01032960
			Before: []byte{
				0x33, 0xc0, 0x74, 0xff, 0xc7, 0xb9, 0x08, 0x00,
				0x00, 0x00, 0x50, 0xe2, 0xfd, 0xc2, 0x67, 0x45,
				0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
			},
			After: []byte{
				// mov eax, [esp+4] (the original format-string argument)
				0x8b, 0x44, 0x24, 0x04,
				// push 0x01079681; push 0x01079650; push eax
				0x68, 0x81, 0x96, 0x07, 0x01,
				0x68, 0x50, 0x96, 0x07, 0x01,
				0x50,
				// call 0x0102d9e0; add esp, 12; ret
				0xe8, 0x6c, 0xb0, 0xff, 0xff,
				0x83, 0xc4, 0x0c,
				0xc3,
			},
		},
		{
			Name:   "banner print call",
			Offset: 0x3208d,                              // VA 0x01032c8d
			Before: []byte{0xe8, 0x4e, 0xad, 0xff, 0xff}, // call 0x0102d9e0
			After:  []byte{0xe8, 0xce, 0xfc, 0xff, 0xff}, // call 0x01032960
		},
	},
}

// MSVC folded each connected/direct pair into one calculation. The first
// immediate is the connected limit and gains twelve in direct mode; the
// second is the direct limit and loses twelve in connected mode. Increasing
// each base by 1024-196 therefore preserves all four historical reservations.
var windowsUserinfoPatch = bytePatch{
	Name: "userinfo",
	Description: fmt.Sprintf(
		"raise the userinfo limit from 196 to 1024 bytes",
		originalLimit,
		patchedLimit,
	),
	Replacements: []replacement{
		{
			Name:   "connect limits",
			Offset: 0xff75,                         // immediate at VA 0x01010b75
			Before: []byte{0xb1, 0x00, 0x00, 0x00}, // 177 / 189
			After:  []byte{0xed, 0x03, 0x00, 0x00}, // 1005 / 1017
		},
		{
			Name:   "setinfo limits",
			Offset: 0x173f6,                        // immediate at VA 0x01017ff6
			Before: []byte{0xc7, 0x00, 0x00, 0x00}, // 199 / 187
			After:  []byte{0x03, 0x04, 0x00, 0x00}, // 1027 / 1015
		},
	},
}
