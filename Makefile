.PHONY: all clean docker

CC ?= cc
ARCH_FLAGS ?= -m32
PATCH_GO_FILES := $(wildcard patch/*.go)

all: qizmo qizmo.exe

clean:
	$(RM) qizmo qizmo.exe qizmo-sound.so qizmo-patch
	$(RM) -r dist

docker:
	docker build \
		--platform linux/amd64 \
		--output type=local,dest=dist \
		.

qizmo: qizmo-2.91 qizmo-patch qizmo-sound.so Makefile
	./qizmo-patch \
		-input qizmo-2.91 \
		-output qizmo

qizmo.exe: qizmo-2.91.exe qizmo-patch Makefile
	./qizmo-patch \
		-input qizmo-2.91.exe \
		-output qizmo.exe

qizmo-patch: $(PATCH_GO_FILES) Makefile
	go build -o qizmo-patch $(PATCH_GO_FILES)

qizmo-sound.so: patch/qizmo-sound.c Makefile
	$(CC) $(ARCH_FLAGS) \
		-fPIC -fno-stack-protector -fno-builtin -fvisibility=hidden \
		-Os -Wall -Wextra -Werror \
		-shared -nostdlib -Wl,--hash-style=sysv -Wl,-s \
		-Wl,-soname,qizmo-sound.so \
		-o qizmo-sound.so patch/qizmo-sound.c \
		-Wl,--no-as-needed -l:libpthread.so.0 -l:libdl.so.2 \
		-Wl,--as-needed
	chmod 755 qizmo-sound.so
