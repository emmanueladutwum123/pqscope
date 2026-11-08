#!/bin/sh
# Rebuilds the test binaries from src/. Needs Docker, and macOS with clang and
# Homebrew openssl@3 for the Mach-O binary. Run from this directory.
set -eu
cd "$(dirname "$0")"

# ELF, dynamically linked against OpenSSL 3.5 (Alpine 3.22).
docker run --rm -v "$PWD:/w" -w /w alpine:3.22 sh -c '
	apk add --no-cache gcc musl-dev openssl-dev >/dev/null
	gcc -O0 -o crypto-elf src/crypto.c -lcrypto
	gcc -O0 -static -s -o constants-elf-stripped src/constants.c'

# PE, importing from a libcrypto DLL through an import library (Debian mingw-w64).
docker run --rm -v "$PWD:/w" -w /w debian:trixie-slim sh -c '
	apt-get update -qq >/dev/null && apt-get install -y -qq gcc-mingw-w64-x86-64 >/dev/null
	x86_64-w64-mingw32-dlltool -d src/libcrypto.def -l /tmp/libcrypto.dll.a
	x86_64-w64-mingw32-gcc -O0 -s -o crypto.exe src/crypto.c /tmp/libcrypto.dll.a'

# Mach-O, dynamically linked against Homebrew OpenSSL.
ssl="$(brew --prefix openssl@3)"
clang -O0 -o crypto-macho src/crypto.c -L"$ssl/lib" -lcrypto

shasum -a 256 crypto-elf constants-elf-stripped crypto.exe crypto-macho
