# syntax=docker/dockerfile:1

FROM debian:trixie-slim AS build

RUN apt-get update \
	&& DEBIAN_FRONTEND=noninteractive \
		apt-get install -y --no-install-recommends \
		gcc-multilib \
		golang-go \
		make \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY Makefile qizmo-2.91 qizmo-2.91.exe ./
COPY patch ./patch

RUN make

FROM scratch AS artifacts

COPY --from=build /src/qizmo /
COPY --from=build /src/qizmo.exe /
COPY --from=build /src/qizmo-sound.so /
