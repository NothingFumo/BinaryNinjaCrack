#!/bin/bash
# 编译 version.dll 代理 (最简方案)
set -e
echo "[*] Building version.dll proxy..."
x86_64-w64-mingw32-gcc -shared -o version.dll \
    version_proxy.c \
    version.def \
    -O2 \
    -Wl,--enable-stdcall-fixup \
    -Wl,-s
echo "[+] Done: version.dll ($(stat -c%s version.dll) bytes)"
