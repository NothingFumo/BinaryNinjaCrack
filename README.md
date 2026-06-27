# Binary Ninja 许可证绕过工具集

Binary Ninja 逆向工程工具的许可证验证绕过方案合集，包含三种攻击路径的分析与实现。

## 方案总览

| 方案 | 原理 | 复杂度 | 推荐度 |
|------|------|--------|--------|
| **version.dll 劫持** | 代理 17 导出 DLL，patch 函数体 | 低 | ★★★ |
| EXE 通用补丁 | 字符串锚点定位 + JNE→JMP | 中 | ★★ |
| RSA 注册机 | 替换公钥 + 生成 license.dat | 高 | ★ |

## 目录结构

```
BinaryNinjaCrack/
├── README.md                          # 本文件
├── doc/
│   ├── analysis.md                    # 完整逆向分析报告
│   └── learning-notes.md             # 破解补丁学习笔记
├── version-dll-hijack/               # 最终方案：version.dll 劫持
│   ├── version_proxy.c               # 代理 DLL 源码 (17 导出)
│   ├── version.def                   # 导出定义
│   ├── build.sh                      # MinGW 编译脚本
│   └── README.md
├── exe-patch/                        # 备选方案：EXE 直接补丁
│   ├── patch_universal.py            # 通用补丁脚本 (字符串锚点)
│   └── README.md
└── keygen/                           # 工具：RSA 注册机
    ├── keygen.py                     # 密钥生成 + license.dat
    └── README.md
```

## 快速使用

### 方案一：version.dll 劫持（推荐）

最简方案，仅需 1 个文件，不修改任何原始文件。

```bash
# 1. 编译
cd version-dll-hijack
bash build.sh

# 2. 部署：复制到 Binary Ninja 安装目录
cp version.dll "D:\BinaryNinja\"

# 3. 启动 Binary Ninja，自动绕过

# 4. 恢复：删除即可
del "D:\BinaryNinja\version.dll"
```

### 方案二：EXE 通用补丁

通过许可证错误字符串自动定位补丁点，兼容多版本。

```bash
cd exe-patch
python patch_universal.py --exe "D:\BinaryNinja\binaryninja.exe"
python patch_universal.py --exe "D:\BinaryNinja\binaryninja.exe" --restore  # 恢复
```

### 方案三：RSA 注册机

生成自定义密钥对，替换 DLL 中的 RSA 公钥。

```bash
cd keygen
python keygen.py          # 生成密钥 + license.dat
```

## 原理简述

Binary Ninja 的许可证验证流程：

```
启动 → 读取 license.dat → RSA 签名验证 → 设置全局标志
  → BNIsLicenseValidated() 返回标志
  → EXE: test al,al; JNZ success
```

三种绕过路径：

1. **函数 patch**：直接修改 `BNIsLicenseValidated` 入口为 `mov eax,1; ret`
2. **跳转 patch**：将 `test al,al; JNE` 改为无条件跳转
3. **密钥替换**：替换 RSA 公钥，用自定义私钥签名 license

## 构建环境

- **编译器**：MinGW-w64 (`x86_64-w64-mingw32-gcc`)
- **Python**：3.8+
- **依赖**：`pycryptodome`（仅 keygen 需要）

## 免责声明

本项目仅供学习逆向工程技术使用。请勿用于非法用途。

## 参考

- [Binary Ninja 官方文档](https://docs.binary.ninja/)
- [Windows DLL Search Order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [x86 Instruction Set Reference](https://www.felixcloutier.com/x86/)
