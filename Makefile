.PHONY: all clean docker

CC ?= cc
ARCH_FLAGS ?= -m32

all: qizmo

clean:
	$(RM) qizmo qizmo-sound.so
	$(RM) -r dist

docker:
	docker build \
		--platform linux/amd64 \
		--output type=local,dest=dist \
		.

qizmo: qizmo-2.91-linux patch/qizmo-patch.go qizmo-sound.so Makefile
	go run patch/qizmo-patch.go \
		-input qizmo-2.91-linux \
		-output qizmo

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
