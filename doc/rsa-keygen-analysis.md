# Binary Ninja v5.3.9434 RSA 公钥逆向分析

> 适用版本：v5.3.9434（binaryninjacore.dll SHA-256 `578b9bb501f3b27722e6e0dfad705479`，`.bak` 原版 `615b9c8c7aadd75dbc8cb68a20a24b91`）
> 使用说明：仅供测试，需要修改 RSA N

## 1. 结论摘要

Binary Ninja 使用 **RSA-2048 / SHA-256 / PKCS#1 v1.5** 签名验证 `license.dat`。RSA 公钥以 **XOR 编码的 SPKI DER 格式**内嵌在 `binaryninjacore.dll` 代码段中，位置与密钥值随版本变化。

| 项目 | 值 |
|------|-----|
| 版本 | 5.3.9434 |
| 密钥长度 | 2048 bit (e=0x10001) |
| 公钥存储 | 296 字节 = SPKI DER (294B) + 2B padding |
| 存储偏移 | 文件偏移 `0x14A33AA`（C7 指令序列） |
| XOR 密钥 | `0x5D65DB32` |
| 原版 N | `d66c9ec8dc86f3db...` |
| 签名算法 | SHA-256 + PKCS#1 v1.5 |

## 2. 公钥存储结构

### 2.1 定位方式（指令模式锚定）

公钥不是存放在数据段，而是由一段 **`mov dword ptr [reg], imm32` 指令序列**在运行时构建。每条指令的 imm32 操作数携带 4 字节编码数据：

```
C7 00 xx xx xx xx          ; mov dword ptr [rax], imm32      (偏移 0x00)
C7 40 04 xx xx xx xx       ; mov dword ptr [rax+0x04], imm32  (偏移 0x04)
C7 40 08 xx xx xx xx       ; mov dword ptr [rax+0x08], imm32
...
C7 80 80 00 00 00 xx xx xx xx   ; mov dword ptr [rax+0x80], imm32
...
```

共 74 条指令 × 4 字节 = **296 字节**。指令模式特征：

| 偏移范围 | 指令形式 |
|----------|----------|
| 0x00 | `C7 00` + imm32 |
| 0x04–0x7C | `C7 40 <disp8>` + imm32 |
| 0x80–0xFC | `C7 80 <disp32>` + imm32 |
| 0x100–0x124 | `C7 80 <disp32+0x100>` + imm32 |

### 2.2 XOR 编码

每个 4 字节小端块先与 XOR 密钥异或，再按字节展开写入 imm32：

```python
for i in range(length):                    # length = 0x128
    rax = i >> 2                           # 所在 4 字节块
    edx = table[rax] ^ xor_key             # table = DER 每 4 字节小端
    shift = (i & 3) << 3                   # 块内字节偏移
    dst[i] = (edx >> shift) & 0xFF
```

XOR 密钥紧邻指令序列之后，通过 `xor reg, imm32`（`35 /r` 或 `81 /6`）指令定位。

### 2.3 解码验证

对 `.bak`（原版）解码得到标准 SPKI DER：

```
30 82 01 22          ; SEQUENCE (0x122)
  30 0D              ; AlgorithmIdentifier
    06 09 2A 86 48 86 F7 0D 01 01 01   ; rsaEncryption
    05 00
  03 82 01 0F 00     ; BIT STRING (0x10F)
    30 82 01 0A       ; SEQUENCE
      02 82 01 01 00 D6 6C 9E C8 ...    ; INTEGER N (257B, 前导 00)
      02 03 01 00 01                    ; INTEGER e = 0x10001
00 00                ; padding
```

## 3. 许可证验证流程

```
license.dat (JSON 数组)
  ├─ product / email / serial / created / type / count / data
  ├─ msg = "\x00".join(上述字段)         # 按序拼接
  ├─ signature = base64(RSA_sign(SHA256(msg), 私钥))
  └─ 程序用内嵌公钥 RSA_verify(SHA256(msg), signature)
```

字段说明：

| 字段 | 示例 | 说明 |
|------|------|------|
| product | `Binary Ninja Personal` | 产品类型 |
| email | 任意字符串 | 邮箱 |
| serial | 32 位 hex | 序列号 |
| created | ISO8601 UTC | 创建时间 |
| type | `User` | 许可类型 |
| count | 整数 | 授权数量 |
| data | base64(0x100 随机 + RC4(8B magic)) | 附加数据 |

`data` 字段结构：`0x100` 字节随机数（MD5 作为 RC4 密钥），加密固定 8 字节 `9C2AAA09A4E2252B0BA125DB1E1CD272207D97CCA8446899` 的前 8 字节，整体 base64。

## 4. keygen 方案（需要修改 RSA N）

由于公钥内嵌在 DLL 中，且密钥值随版本变化，注册机方案为：

```
1. 生成新 RSA-2048 密钥对（或使用内置密钥对）
2. 公钥 → SPKI DER → XOR 编码 → 替换 DLL 中 296 字节 N 存储区
3. 用私钥签名 license.dat
4. 将 license.dat 放入 Binary Ninja 安装目录
```

**需要修改 RSA N**：必须把 DLL 中内嵌的原版公钥 N 替换为自定义密钥对的公钥 N，否则用自定义私钥签发的 license 无法通过原版公钥验签。

### 4.1 替换流程

```
定位指令模式 → 收集 296 个 imm32 操作数偏移 → 定位 XOR 密钥
→ 新公钥 DER → transform(table, 0x128, xor_key) → 逐字节写回
```

### 4.2 版本差异处理

- 各版本 `binaryninjacore.dll` 的指令模式相同，**XOR 密钥可能不同**
- 原版公钥 N 值不同 → 需从对应版本的 `.bak` 中提取
- 本实现从 DLL 动态提取 XOR 密钥，不硬编码

## 5. 版本指纹

| 文件 | SHA-256 | N 前 8 字节 | 状态 |
|------|---------|-------------|------|
| binaryninjacore.dll | `578b9bb5...` | `a6c4ff734b90b755` | 已替换（未知密钥对） |
| binaryninjacore.dll.bak | `615b9c8c...` | `d66c9ec8dc86f3db` | 官方原版 |
| binaryninjacore_patched.dll | `81d5606e...` | `ed4a892838114695` | 已替换（未知密钥对） |

> 当前安装目录的 DLL 与 `license.dat` 不匹配（现有 license 无法用任一 DLL 内 N 验签通过），
> 需用本 keygen 重新生成密钥对、替换 N、签发 license 后三者才一致。
