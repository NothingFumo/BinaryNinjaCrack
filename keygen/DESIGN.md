# keygen 单文件方案设计

> 适用版本：v5.3.9434，其它版本自测
> 使用说明：仅供测试、需要修改 RSA N

## 1. 设计目标

将 keygen 收敛为**单文件**脚本，使用风格与 `exe-patch/patch_universal.py` 对齐（扁平参数），
一键完成"生成密钥 → 替换 DLL 中 RSA N → 签发 license"。

| 需求 | 实现 |
|------|------|
| 单文件 | 定位/替换、密钥、license 签发、CLI 合并于 `keygen.py` |
| 一键流程 | 默认运行：生成密钥（复用已有）→ patch → license |
| 工作目录 | 默认脚本所在目录，`--work-dir` 指定（密钥存放处） |
| license 位置 | 默认 DLL 所在目录，`--license-dir` 指定 |
| 可恢复 | `--restore` 从 `.bak` 还原；patch 前自动备份 |
| 可预览 | `--dry-run` 仅定位不写入 |
| 可校验 | `--verify` 检查 DLL 中 N 与私钥匹配；写回后自校验 |

## 2. 模块划分（单文件内分段）

```
keygen.py
├── 常量        KEY_BITS / PATCH_LENGTH / DATA_MAGIC
├── 模块 A      DLL 公钥定位与替换
│   ├── build_pattern_instructions()   74 条 C7 指令模板
│   ├── locate_operands()              模式搜索 → 操作数偏移
│   ├── locate_xor_key()               XOR 密钥定位
│   ├── xor_encode/decode_pubkey()     编解码（对称逆运算）
│   ├── extract_pubkey_der()           提取当前 N
│   ├── patch_pubkey()                 替换 N（备份 + 写回自校验）
│   └── restore_pubkey()               从 .bak 还原
├── 模块 B      RSA 密钥与 license
│   ├── generate_keypair()             生成 RSA-2048
│   ├── generate_license()             构造 7 字段 + SHA256 + PKCS1v1.5 签名
│   └── verify_license()               验签
└── 模块 C      CLI（扁平参数，对齐 exe-patch / deploy.py）
    ├── resolve_dll()     位置参数：目录 → 目录/DLL；文件 → 直接用；无 → 自动查找
    └── main()            target / --dll / --restore / --dry-run /
                           --extract / --verify / --work-dir /
                           --license-dir / --email / --count
```

## 3. 关键算法

### 3.1 公钥存储（逆向结论）

- 位置：`binaryninjacore.dll` 偏移 `0x14A33AA`（v5.3.9434）
- 结构：74 条 `mov dword ptr [reg+disp], imm32` × 4B = 296B
- 编码：SPKI DER 每 4 字节小端 XOR `0x5D65DB32` 后逐字节展开
- 解码：XOR 密钥紧邻指令序列后，由 `xor reg, imm32` 指令定位（动态，不硬编码）

### 3.2 license 结构

```
msg = product \x00 email \x00 serial \x00 created \x00 type \x00 count \x00 data
signature = PKCS1v1.5_sign(SHA256(msg))
data = base64(0x100 随机 + RC4(MD5(随机), 8B magic))
```

### 3.3 一键流程

```
目标解析：位置参数（目录/DLL）或 --dll，缺省 → 当前目录/脚本目录查找
工作目录无私钥 → 生成 rsa_private.pem / rsa_public.pem
定位模式 + XOR 密钥 → 打印 当前N / 新N
dry-run? → 结束
patch：备份 .bak → 编码新 DER → 写回 296 字节 → 重新提取对比（自校验）
license：签发 license.dat 到 --license-dir（默认 DLL 所在目录 = 安装目录）
```

## 4. 验证

- 副本 DLL 端到端：extract 原版 N → 一键 → verify 匹配 → restore 还原
- 幂等：重复一键复用已有密钥对
- 恢复：`.bak` 不被二次 patch 覆盖
