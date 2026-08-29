# Qizmo 2.91

Qizmo is a QuakeWorld proxy written by Juha Kujala and Ilkka Rajala.
This repository preserves the original Qizmo 2.91 Linux release and adds
small compatibility fixes for modern Linux systems and QuakeWorld clients.

Qizmo remains the work of its original authors and is distributed under
the terms stated in the original documentation. The compatibility work
does not grant any additional rights to the original program.

## Compatibility fixes

The patcher applies four independently validated patches to the original
`qizmo-2.91-linux` executable:

1. **Integrity:** removes the executable integrity check and its failure
   path so that compatibility patches can be applied.
2. **Banner:** adds the compatibility attribution and this repository's
   URL without replacing another Qizmo message.
3. **Userinfo:** raises Qizmo's userinfo limit from 196 to 1024 bytes
   while preserving the space reserved for Qizmo's own keys.
4. **Sound:** adds `qizmo-sound.so` as an ordinary ELF dependency. The
   library implements the OSS interface and microphone callbacks expected
   by Qizmo using ALSA on modern Linux.

Qizmo's sound system still loads and mixes Quake sounds and performs its
original voice encoding, decoding, transport, and demo recording. The
compatibility library only connects those existing systems to ALSA on
modern Linux.

## Building

The build requires Go 1.20 or newer, a C compiler capable of producing
32-bit x86 binaries, and the 32-bit `libpthread` and `libdl` runtime
libraries. Sound playback and capture require the 32-bit
`libasound.so.2` runtime library.

### Docker

Docker is the easiest option when the host does not have a 32-bit build
environment. Build for `linux/amd64` and export the two generated files
to `dist/` with:

```sh
make docker
```

This target runs the equivalent Docker command:

```sh
docker build \
    --platform linux/amd64 \
    --output type=local,dest=dist \
    .
```

The final container stage contains only `qizmo` and `qizmo-sound.so`, so
the local output directory receives those files directly.

### Debian 13

On a 64-bit Debian 13 system, enable the i386 architecture and install
the native build and runtime dependencies with:

```sh
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get install --no-install-recommends \
    gcc-multilib \
    golang-go \
    libasound2t64:i386 \
    make
```

Then build the sound compatibility library and patched executable with:

```sh
make
```

This produces:

- `qizmo` — the patched executable.
- `qizmo-sound.so` — the Linux ALSA compatibility library.

The patcher can also be run directly:

```sh
go run patch/qizmo-patch.go \
    -input /path/to/qizmo-2.91-linux \
    -output /path/to/qizmo
```

The patcher accepts only the exact original Qizmo 2.91 Linux executable
or an executable it has already patched. Every replacement validates the
bytes at its expected location, and the complete output is verified
against its known SHA-256 digest.

## Running on Linux

Keep `qizmo-sound.so` next to the patched `qizmo` executable. Run Qizmo
from the release directory so it can also find `compress.dat` and its
configuration files:

```sh
./qizmo -a your_admin_password -b /path/to/quake
```

Start the QuakeWorld client manually. When using Qizmo's sound system for
game sounds and voice playback, retain the original recommendation to
start the client with `-nosound`, then connect it to the proxy:

```text
connect localhost
```

Use Qizmo's **Sound system** menu to enable game sounds, voice-channel
playback, and sound capture. The special voice channel named `feedback`
sends your microphone input back to you and is useful for testing.

## Repository contents

- `qizmo-2.91-linux` is the untouched original Linux executable.
- `patch/qizmo-patch.go` applies the compatibility patches.
- `patch/qizmo-sound.c` is the Linux sound compatibility library.
- [readme.txt](readme.txt) is the unmodified original Qizmo 2.91
  manual.
- The remaining data and configuration files come from the original
  Qizmo 2.91 release.

## Original documentation

The complete original Qizmo 2.91 manual is preserved in
[readme.txt](readme.txt). Historical platform support, addresses, and
registration information may no longer be current.
