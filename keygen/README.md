# RSA 注册机（Binary Ninja 授权生成器）

> 适用版本：v5.3.9434，其它版本自测
> 使用说明：仅供测试、需要修改 RSA N

重新实现后的模块化 keygen：生成密钥对 → 替换 `binaryninjacore.dll` 中内嵌的 RSA 公钥 N → 用私钥签发 `license.dat`。

## 原理

Binary Ninja 用 RSA-2048 验签 license.dat（SHA-256 + PKCS#1 v1.5）。公钥 N 以 XOR 编码的 SPKI DER（296 字节）内嵌在 DLL 的 C7 指令序列中。**需要修改 RSA N**：必须把 DLL 中的原版公钥替换为自定义密钥对的公钥，license 才能验签通过。详见 [`doc/rsa-keygen-analysis.md`](../doc/rsa-keygen-analysis.md)。

## 使用

依赖：`pip install pycryptodome`

```bash
# 1. 生成密钥对
python keygen.py genkey --out-dir keys

# 2. 替换 DLL 中 RSA N（自动备份 .bak，可 restore 还原）
python keygen.py patch "D:\BinaryNinja\binaryninjacore.dll" --key keys\rsa_public.pem

# 3. 生成 license.dat（放入 Binary Ninja 安装目录）
python keygen.py license --key keys\rsa_private.pem --email you@example.com --count 999

# 4. 校验（可选）
python keygen.py verify "D:\BinaryNinja\binaryninjacore.dll" --key keys\rsa_private.pem --license license.dat
```

## 子命令

| 命令 | 说明 |
|------|------|
| `extract <dll> [--out der]` | 提取 DLL 中当前公钥 N（hex/DER） |
| `genkey [--out-dir .]` | 生成 RSA-2048 密钥对 |
| `patch <dll> --key pub.pem` | 替换 DLL 中 N（自动备份 `.bak`，写回自校验） |
| `restore <dll>` | 从 `.bak` 恢复原版 DLL |
| `license --key priv.pem` | 生成 license.dat（`--email/--count/--serial/--product/--type`） |
| `verify <dll> --key priv.pem` | 校验 DLL 中 N 与私钥匹配，可选验签 license |

## 文件

| 文件 | 说明 |
|------|------|
| `keygen.py` | CLI 入口 |
| `bn_rsa.py` | 密钥对生成、DER 编码、license 签发/验证 |
| `bn_patch.py` | DLL 中 N 的定位（指令模式 + XOR 密钥）、提取、替换、备份/恢复 |
| `DESIGN.md` | 重新实现方案设计 |

## 注意事项

- patch 前自动备份 `binaryninjacore.dll.bak`；重复 patch 不覆盖已有备份
- 密钥文件与 `license.dat` 已被 `.gitignore` 排除，不入库
- 版本升级后需重新提取 XOR 密钥（本实现动态定位，不硬编码偏移）
