# Binary Ninja 许可证逆向分析报告

## 1. 目标概述

- **软件**：Binary Ninja（商业逆向工程工具）
- **验证机制**：RSA 签名验证
- **分析日期**：2026-06-06

## 2. 程序架构

```
binaryninja.exe (主程序, 24.6 MB)
  ├── binaryninjaui.dll      (UI 层, 1181 imports)
  ├── Qt6Widgets.dll          (Qt 控件)
  ├── Qt6Gui.dll              (Qt GUI)
  ├── Qt6Core.dll             (Qt 核心, 导入 version.dll / winmm.dll)
  └── binaryninjacore.dll     (核心库, 3561 exports)
        ├── BNIsLicenseValidated @ RVA 0x14A59B0
        ├── BNSetLicense @ RVA 0x14A5A00
        └── RSA 公钥 N @ RVA 0x014A3FAA (643 字节, XOR 编码)
```

## 3. 许可证验证流程

```
启动
  ↓
读取 license.dat
  ↓
RSA 公钥验签 (N + e=0x10001)
  ↓
设置全局标志
  ↓
BNIsLicenseValidated() → 返回 al=0/1
  ↓
EXE: test al,al; JNZ success
  ↓
失败 → 试用模式
```

## 4. 可劫持 DLL 分析

Qt6Core.dll 的导入表中可劫持的 DLL：

| DLL | 导出数 | KnownDLLs | 可劫持 | 推荐度 |
|-----|--------|-----------|--------|--------|
| **VERSION.dll** | **17** | **否** | **✓** | **★★★** |
| WINMM.dll | 181 | 否 | ✓ | ★★ |
| MSVCP140_1.dll | 7 | 否 | ✓ | ★★ |
| VCRUNTIME140_1.dll | 3 | 否 | ✓ | ★★ |
| MPR.dll | 85 | 否 | ✓ | ★ |
| AUTHZ.dll | 68 | 否 | ✓ | ★ |

## 5. 关键函数定位

```python
# BNIsLicenseValidated
import pefile
pe = pefile.PE('binaryninjacore.dll')
for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    if exp.name and b'LicenseValidated' in exp.name:
        print(f'{exp.name.decode()}  RVA=0x{exp.address:X}')
# 输出: BNIsLicenseValidated  RVA=0x14A59B0  ordinal=2279
```

## 6. EXE 检查逻辑

```
0x140114806: call 0x140333410    ; 许可证验证函数
0x14011480B: test al, al         ; 检查返回值
0x14011480D: jnz 0x140115013     ; 有效则跳转
0x140114813: test sil, sil       ; 无效则继续
```

## 7. 三种绕过方案

### 方案 A：version.dll 函数 patch（最终方案）

代理 version.dll，在 DllMain 中 patch `BNIsLicenseValidated` 函数入口：

```c
// mov eax, 1; ret — 永远返回 TRUE
addr[0] = 0xB8;  addr[1] = 0x01;
addr[2] = 0x00;  addr[3] = 0x00;
addr[4] = 0x00;  addr[5] = 0xC3;
```

**优势**：17 导出，21KB，无外部依赖，不修改原始文件。

### 方案 B：EXE 跳转 patch

将 `test al,al; JNE` 改为无条件跳转：

```
补丁前: 0F 85 00 08 00 00  (JNE +0x800)
补丁后: E9 01 08 00 00 90  (JMP +0x801, NOP)
```

使用字符串锚点自动定位，兼容多版本。

### 方案 C：RSA 公钥替换

替换 binaryninjacore.dll 中的 RSA 公钥 N (643 字节)，配合自定义私钥生成的 license.dat。

## 8. 方案对比

| 维度 | version.dll 劫持 | EXE 跳转 patch | RSA 替换 |
|------|-----------------|---------------|----------|
| 修改原始文件 | 否 | 是 | 是 |
| 代理 DLL | 17 导出 / 21KB | 无 | 无 |
| 外部依赖 | 无 | 无 | license.dat |
| 版本兼容 | 高 | 中 | 中 |
| 复杂度 | 低 | 中 | 高 |
| 更新后重做 | 否 | 是 | 是 |

## 9. 技术要点总结

1. **DLL 搜索顺序**：应用程序目录优先于 System32，这是 DLL 劫持的基础
2. **函数 patch vs 跳转 patch**：patch 核心函数入口比 patch EXE 跳转更通用
3. **字符串锚点**：利用 UI 文本作为语义锚点，比固定偏移更抗版本变化
4. **最小攻击面**：选择导出数最少的 DLL (version.dll) 降低复杂度和检测风险
5. **内存 patch**：VirtualProtect → 改写 → FlushInstructionCache 是标准三步
