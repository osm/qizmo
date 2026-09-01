package main

import (
	"bytes"
	"fmt"
)

const (
	linuxOriginalSHA256 = "db4e91bbc40a03e422c4ebec1e1a27a1" +
		"45bdd0bbcd0fb498741b6281c92ee8ef"
	linuxPatchedSHA256 = "d89552a997a5210be790a315e0ad2915" +
		"2988de38b9a473e3d69ad3677a98951e"
)

// Integrity patch

// Qizmo's original startup integrity mechanism XORs every 32-bit word in
// its own executable and expects the result to be zero. The executable was
// crafted to satisfy that checksum. On success the scanner replaces a
// callback that initially points at a recursive trap with a no-op callback.
// Any ordinary binary patch changes the XOR and therefore leaves the trap
// selected.
//
// Merely initializing the callback to the success value avoids the trap,
// but still makes Qizmo open and scan the entire executable on every start.
// Retire the mechanism completely instead:
//
//  1. Jump over the scanner call while retaining the surrounding push/add
//     pair, so the caller's stack behavior is unchanged.
//  2. Jump over the later indirect callback invocation.
//  3. Jump over the callback comparison and integrity-failure handler.
//
// The skipped scanner and its two callbacks then have no remaining callers.
// Their bytes are deliberately left intact for forensic comparison and may
// be overwritten by later feature patches using the cave map below.
var linuxIntegrityPatch = bytePatch{
	Name:        "integrity",
	Description: "remove the integrity check",
	Replacements: []replacement{
		{
			Name:   "skip executable scanner",
			Offset: 0x5afcc,
			Before: []byte{0xe8, 0x1b}, // call 0x08072cec
			After:  []byte{0xeb, 0x03}, // jmp  0x080a2fd1
		},
		{
			Name:   "skip integrity callback",
			Offset: 0x5bc63,
			Before: []byte{0xa1, 0x30}, // mov eax, [0x080d0b30]
			After:  []byte{0xeb, 0x05}, // jmp 0x080a3c6a
		},
		{
			Name:   "skip integrity failure guard",
			Offset: 0x5be1f,
			Before: []byte{0x8b, 0x0d}, // mov ecx, [0x080d0b4c]
			After:  []byte{0xeb, 0x3f}, // jmp 0x080a3e60
		},
	},
}

// After the banner patch, the retired integrity mechanism leaves these code
// caves available for later patches. File offsets are listed first,
// followed by virtual addresses and sizes:
//
//   0x2aceb / 0x08072ceb: 213 executable bytes, through 0x08072dbf
//   0x5afce / 0x080a2fce:   3 executable bytes
//   0x5bc65 / 0x080a3c65:   5 executable bytes
//   0x5be2e / 0x080a3e2e:  50 executable bytes
//   0x5e57b / 0x080a657b:   1 executable byte
//   0x87ac0 / 0x080d0ac0:  33 writable data bytes
//
// Total: 272 executable bytes and 33 writable data bytes.

// Banner patch

// The integrity patch makes Qizmo's recursive trap and encoded warning
// data unreachable. Reuse those bytes for two tiny printf trampolines, the
// attribution string, and the repository URL. Both strings are stored at
// the end of the retired data so that the remaining 33-byte data cave stays
// contiguous. Replacing the existing "\nF" banner boundary and its final
// "\n\n" with same-size "%s" placeholders keeps the original banner
// exactly the same size and does not change any other message.
var linuxBannerPatch = bytePatch{
	Name:        "banner",
	Description: "add the compatibility attribution and repository URL",
	Replacements: []replacement{
		{
			Name:   "repository URL storage",
			Offset: 0x87ae1,
			Before: []byte{
				0xdb, 0x85, 0x8f, 0xdd, 0xd3, 0x85,
				0x8d, 0xdc, 0xe1, 0xd7, 0x85, 0x90,
				0xe2, 0xe1, 0xe3, 0xd9, 0xc8, 0xd7,
				0xdd, 0xd8, 0xdd, 0x8e, 0x81, 0xcf,
				0xd2, 0x84, 0x99, 0xe8, 0xe4, 0x95,
				0x83, 0xc4, 0xcf, 0x8e,
			},
			After: []byte(
				" | https://github.com/osm/qizmo" +
					"\n\n\x00",
			),
		},
		{
			Name:   "attribution storage",
			Offset: 0x87b03,
			Before: []byte{
				0x8b, 0xd4, 0xdc, 0xe6, 0x7d, 0x6b,
				0xcd, 0xd8, 0x8c, 0x84, 0xc5, 0xd5,
				0xd5, 0x81, 0x8f, 0xdd, 0x8e, 0x99,
				0xe8, 0xe4, 0xe7, 0x92, 0x88, 0xc9,
				0xd3, 0xd6, 0x84, 0x84, 0xcd, 0xdc,
				0xde, 0x8b, 0x87, 0xd6, 0xde, 0xd3,
				0xc6, 0xdb, 0xde, 0x93, 0x38, 0x0a,
				0x00, 0x00, 0x00, 0x70, 0x65, 0x0a,
				0x08,
			},
			After: []byte(
				"\nCompatibility fixes by " +
					"Oscar Linderholm, 2026\nF\x00",
			),
		},
		{
			Name:   "banner format placeholder",
			Offset: 0x7da3b,
			Before: []byte("\nF"),
			After:  []byte("%s"),
		},
		{
			Name:   "repository URL format placeholder",
			Offset: 0x7da8f,
			Before: []byte("\n\n"),
			After:  []byte("%s"),
		},
		{
			Name:   "banner printf trampoline",
			Offset: 0x5e56e,
			Before: []byte{
				0x89, 0xf6, 0x55, 0x89, 0xe5, 0xe8, 0xf8,
				0xff, 0xff, 0xff, 0x89, 0xec, 0x5d,
			},
			After: []byte{
				// movl $0x080d0b03, 8(%esp)
				0xc7, 0x44, 0x24, 0x08, 0x03, 0x0b,
				0x0d, 0x08,
				// jmp 0x080a3e21
				0xe9, 0xa6, 0xd8, 0xff, 0xff,
			},
		},
		{
			Name:   "repository URL argument trampoline",
			Offset: 0x5be21,
			Before: []byte{
				0x4c, 0x0b, 0x0d, 0x08, 0x81, 0xb9, 0x50,
				0x35, 0x00, 0x00, 0x70, 0x65, 0x0a,
			},
			After: []byte{
				// movl $0x080d0ae1, 12(%esp)
				0xc7, 0x44, 0x24, 0x0c, 0xe1, 0x0a,
				0x0d, 0x08,
				// jmp 0x080727a8
				0xe9, 0x7a, 0xe9, 0xfc, 0xff,
			},
		},
		{
			Name:   "banner print call",
			Offset: 0x5ae96,
			// call 0x080727a8
			Before: []byte{0xe8, 0x0d, 0xf9, 0xfc, 0xff},
			// call 0x080a656e
			After: []byte{0xe8, 0xd3, 0x36, 0x00, 0x00},
		},
	},
}

// Userinfo patch

// Qizmo reserves different amounts of userinfo space for its own keys in
// each path. Add 1024 - 196 to every historical threshold so those
// reservations are preserved while adopting the modern QuakeWorld limit.
var linuxUserinfoPatch = bytePatch{
	Name: "userinfo",
	Description: fmt.Sprintf(
		"raise the userinfo limit from %d to %d bytes",
		originalLimit,
		patchedLimit,
	),
	Replacements: []replacement{
		{
			Name:   "connect limit (connected mode)",
			Offset: 0x31023,
			Before: []byte{0xb1, 0x00, 0x00, 0x00}, // 177
			After:  []byte{0xed, 0x03, 0x00, 0x00}, // 1005
		},
		{
			Name:   "connect limit (direct mode)",
			Offset: 0x31034,
			Before: []byte{0xbd, 0x00, 0x00, 0x00}, // 189
			After:  []byte{0xf9, 0x03, 0x00, 0x00}, // 1017
		},
		{
			Name:   "setinfo limit (connected mode)",
			Offset: 0x3a393,
			Before: []byte{0xbb, 0x00, 0x00, 0x00}, // 187
			After:  []byte{0xf7, 0x03, 0x00, 0x00}, // 1015
		},
		{
			Name:   "setinfo limit (direct mode)",
			Offset: 0x3a3de,
			Before: []byte{0xc7, 0x00, 0x00, 0x00}, // 199
			After:  []byte{0x03, 0x04, 0x00, 0x00}, // 1027
		},
	},
}

// Sound dependency patch

const soundLibraryDependency = "$ORIGIN/qizmo-sound.so"

// Qizmo is already a dynamically linked ELF executable. Make the Linux
// sound compatibility driver an ordinary dependency so the system loader
// maps it before Qizmo starts and its constructor can install the capture
// callbacks and OSS compatibility hooks. This removes the need for a
// preload launcher.
//
// The original .dynamic section has only its terminating DT_NULL entry, but
// it is followed by enough zero padding for one additional entry. Turn the
// old terminator into DT_NEEDED and extend the section and its containing
// segment by eight bytes so the existing padding becomes the new
// terminator.
//
// There is no unused 23-byte run in .dynstr for "$ORIGIN/qizmo-sound.so".
// Preserve the string table's size and every exported/imported symbol name
// by sharing existing suffixes:
//
//	printf   -> the "printf" suffix in "vsprintf"
//	sprintf  -> the "sprintf" suffix in "vsprintf"
//	environ  -> the "environ" suffix in "__environ"
//	_start   -> the "_start" suffix in "__bss_start"
//
// Move _etext and _edata into the former standalone printf/sprintf storage.
// Their old storage then joins the standalone environ/_start storage into a
// 29-byte run, large enough for the dependency and six trailing zero bytes.
// The dynamic symbol table still resolves to exactly the same names.
var linuxSoundPatch = bytePatch{
	Name:        "sound",
	Description: "load qizmo-sound.so through ELF metadata",
	Replacements: []replacement{
		{
			Name:   "relocated _etext and _edata names",
			Offset: 0xd21,
			Before: []byte("printf\x00sprintf\x00"),
			After:  []byte("_etext\x00_edata\x00\x00"),
		},
		{
			Name:   "sound dependency name",
			Offset: 0xf31,
			Before: []byte(
				"environ\x00_start\x00" +
					"_etext\x00_edata\x00",
			),
			After: []byte(
				soundLibraryDependency +
					"\x00\x00\x00" +
					"\x00\x00\x00\x00",
			),
		},
		{
			Name:   "printf name suffix",
			Offset: 0x6ec,
			Before: []byte{0x75, 0x01, 0x00, 0x00},
			After:  []byte{0x86, 0x01, 0x00, 0x00},
		},
		{
			Name:   "sprintf name suffix",
			Offset: 0x6fc,
			Before: []byte{0x7c, 0x01, 0x00, 0x00},
			After:  []byte{0x85, 0x01, 0x00, 0x00},
		},
		{
			Name:   "environ name suffix",
			Offset: 0xb4c,
			Before: []byte{0x85, 0x03, 0x00, 0x00},
			After:  []byte{0x7d, 0x03, 0x00, 0x00},
		},
		{
			Name:   "_start name suffix",
			Offset: 0xb5c,
			Before: []byte{0x8d, 0x03, 0x00, 0x00},
			After:  []byte{0xa7, 0x03, 0x00, 0x00},
		},
		{
			Name:   "_etext relocated name",
			Offset: 0xb6c,
			Before: []byte{0x94, 0x03, 0x00, 0x00},
			After:  []byte{0x75, 0x01, 0x00, 0x00},
		},
		{
			Name:   "_edata relocated name",
			Offset: 0xb7c,
			Before: []byte{0x9b, 0x03, 0x00, 0x00},
			After:  []byte{0x7c, 0x01, 0x00, 0x00},
		},
		{
			Name:   "sound DT_NEEDED entry",
			Offset: 0x88e40,
			Before: []byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00,
			},
			After: []byte{
				0x01, 0x00, 0x00, 0x00, 0x85, 0x03,
				0x00, 0x00,
			},
		},
		{
			Name:   "writable load segment file size",
			Offset: 0xa4,
			Before: []byte{0xa8, 0x5f, 0x00, 0x00},
			After:  []byte{0xb0, 0x5f, 0x00, 0x00},
		},
		{
			Name:   "dynamic segment sizes",
			Offset: 0xc4,
			Before: []byte{
				0x90, 0x00, 0x00, 0x00, 0x90, 0x00,
				0x00, 0x00,
			},
			After: []byte{
				0x98, 0x00, 0x00, 0x00, 0x98, 0x00,
				0x00, 0x00,
			},
		},
		{
			Name:   "dynamic section size",
			Offset: 0x8a4ec,
			Before: []byte{0x90, 0x00, 0x00, 0x00},
			After:  []byte{0x98, 0x00, 0x00, 0x00},
		},
	},
}

var linuxPatches = []patch{
	linuxIntegrityPatch,
	linuxBannerPatch,
	linuxUserinfoPatch,
	linuxSoundPatch,
}

func patchLinux(
	input []byte,
	inputDigest string,
) (*patchResult, bool, error) {
	switch inputDigest {
	case linuxPatchedSHA256:
		return &patchResult{
			Output:   bytes.Clone(input),
			Platform: "linux",
		}, true, nil
	case linuxOriginalSHA256:
		output, steps, err := applyPatchSequence(
			input,
			linuxPatches,
			nil,
			linuxPatchedSHA256,
		)
		if err != nil {
			return nil, true, err
		}
		return &patchResult{
			Output:   output,
			Changed:  true,
			Platform: "linux",
			Steps:    steps,
		}, true, nil
	default:
		return nil, false, nil
	}
}
