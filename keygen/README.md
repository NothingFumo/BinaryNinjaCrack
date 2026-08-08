# RSA 注册机（Binary Ninja 授权生成器 · 单文件版）

> 适用版本：v5.3.9434，其它版本自测
> 使用说明：仅供测试、需要修改 RSA N

单文件 keygen：生成密钥对 → 替换 `binaryninjacore.dll` 中内嵌的 RSA 公钥 N → 用私钥签发 `license.dat`。

## 原理

Binary Ninja 用 RSA-2048 验签 license.dat（SHA-256 + PKCS#1 v1.5）。公钥 N 以 XOR 编码的 SPKI DER（296 字节）内嵌在 DLL 的 C7 指令序列中。**需要修改 RSA N**：必须把 DLL 中的原版公钥替换为自定义密钥对的公钥，license 才能验签通过。详见 [`doc/rsa-keygen-analysis.md`](../doc/rsa-keygen-analysis.md)。

## 使用

依赖：`pip install pycryptodome`

```bash
cd keygen

# 一键：生成密钥 → 替换 DLL 中 N → 生成 license.dat（默认输出到 DLL 所在目录）
python keygen.py --dll "D:\BinaryNinja\binaryninjacore.dll"

# 恢复：从自动备份的 .bak 还原原版 DLL
python keygen.py --dll "D:\BinaryNinja\binaryninjacore.dll" --restore

# 仅分析：查看当前 N 与补丁位置，不写入
python keygen.py --dll "D:\BinaryNinja\binaryninjacore.dll" --dry-run

# 提取当前 N
python keygen.py --dll "D:\BinaryNinja\binaryninjacore.dll" --extract

# 校验 DLL 中 N 与工作目录私钥是否匹配
python keygen.py --dll "D:\BinaryNinja\binaryninjacore.dll" --verify
```

## 参数

| 参数 | 说明 |
|------|------|
| `--dll` | binaryninjacore.dll 路径（省略时自动查找当前目录/脚本目录） |
| `--work-dir` | 工作目录（密钥存放，**默认脚本所在目录**） |
| `--license-dir` | license 输出目录（默认 DLL 所在目录） |
| `--restore` | 从 `.bak` 恢复原版 DLL |
| `--dry-run` | 仅分析定位，不写入 |
| `--extract` | 仅提取 DLL 当前 N |
| `--verify` | 校验 DLL 中 N 与工作目录私钥匹配 |
| `--email` / `--count` / `--serial` | license 内容定制 |
| `--no-backup` | patch 前不备份 `.bak` |

## 生成文件

| 文件 | 位置 | 说明 |
|------|------|------|
| `rsa_private.pem` / `rsa_public.pem` | 工作目录 | 密钥对（已存在则复用） |
| `<dll>.bak` | DLL 同目录 | 原版备份（patch 前自动生成） |
| `license.dat` | DLL 所在目录 | 许可证 |

## 部署提示

- license.dat 需放入 Binary Ninja 实际读取路径：`%APPDATA%\Binary Ninja\license.dat`（安装目录中的同名文件不生效）
- 密钥文件与 `license.dat` 已被 `.gitignore` 排除，不入库
- 版本升级覆盖 DLL 后需重新执行一键
- 动态定位指令模式与 XOR 密钥，不硬编码偏移
