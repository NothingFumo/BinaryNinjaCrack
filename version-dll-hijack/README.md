# version.dll 劫持方案

最简 DLL 劫持方案，代理 version.dll (17 个导出)，直接 patch `BNIsLicenseValidated` 函数体。

## 原理

```
Qt6Core.dll → 导入 version.dll
      ↓
代理 version.dll (应用目录优先加载)
      ↓
DllMain:
  1. LoadLibrary("C:\Windows\System32\version.dll")  — 加载真实 DLL
  2. GetProcAddress × 17                              — 解析函数指针
  3. GetProcAddress("BNIsLicenseValidated")           — 定位目标函数
  4. patch 函数入口: mov eax, 1; ret                   — 强制返回 TRUE
      ↓
17 个 C 转发桩 → 真实 version.dll
```

## 关键技术点

### DLL 搜索顺序劫持

Windows DLL 搜索顺序中，**应用程序目录**优先于 System32。在 Binary Ninja 安装目录放置同名 `version.dll` 即可劫持加载。

### 为什么选择 version.dll

Qt6Core.dll 导入了多个可劫持的 DLL：

| DLL | 导出数 | 推荐度 |
|-----|--------|--------|
| **version.dll** | **17** | **★★★ 最佳** |
| winmm.dll | 180 | ★★ |
| VCRUNTIME140_1.dll | 3 | ★ |

version.dll 导出最少，体积最小，无外部依赖。

### 函数 patch 而非跳转 patch

不修改 EXE 的 `test al,al; JNE` 指令，而是直接 patch 核心函数入口：

```c
// BNIsLicenseValidated 原始入口可能有几十字节
// 直接覆盖为 6 字节：mov eax, 1; ret
addr[0] = 0xB8;  // mov eax, imm32
addr[1] = 0x01;
addr[2] = 0x00;
addr[3] = 0x00;
addr[4] = 0x00;
addr[5] = 0xC3;  // ret
```

优势：不依赖 IAT RVA，不依赖 EXE 版本，通用性强。

## 文件说明

| 文件 | 说明 |
|------|------|
| `version_proxy.c` | 代理 DLL 完整源码 |
| `version.def` | 17 个导出函数定义 |
| `build.sh` | MinGW 编译脚本 |

## 编译

```bash
# 需要 MinGW-w64
x86_64-w64-mingw32-gcc -shared -o version.dll \
    version_proxy.c version.def \
    -O2 -Wl,--enable-stdcall-fixup -Wl,-s
```

## 部署

```bash
cp version.dll "D:\BinaryNinja\"
# 启动 Binary Ninja 即可
```

## 恢复

```bash
del "D:\BinaryNinja\version.dll"
```
