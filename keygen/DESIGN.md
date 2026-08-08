# keygen 重新实现方案设计

> 适用版本：v5.3.9434，其它版本自测
> 使用说明：仅供测试、需要修改 RSA N

## 1. 目标

重新实现 `keygen/` 目录下的 RSA 注册机，解决旧实现的问题：

| 问题 | 说明 |
|------|------|
| 单文件大杂烩 | 265 行混排模式搜索、XOR 定位、补丁、license 生成 |
| 密钥硬编码 | 私钥/公钥以超长 hex 内嵌，无法替换 |
| 无参数化 | 邮箱/数量/序列号写死，DLL 路径写死 |
| 不可独立验证 | 无法单独验证 DLL 中 N 是否与私钥匹配 |
| 无备份恢复 | patch 前不备份，无法还原原版 N |

## 2. 设计

### 2.1 模块划分

```
keygen/
├── keygen.py          # 主入口，argparse CLI 子命令
├── bn_rsa.py          # 密钥对生成、DER 编解码、license 签名
├── bn_patch.py        # DLL 定位：指令模式、XOR 密钥、N 提取/替换
└── README.md          # 使用文档
```

### 2.2 CLI 接口

```
python keygen.py extract  <dll>            # 提取 DLL 中当前 N，输出 hex/PEM
python keygen.py genkey   [--out-dir .]    # 生成新 RSA-2048 密钥对
python keygen.py patch    <dll> --key rsa_public.pem   # 替换 DLL 中 N（自动备份 .bak）
python keygen.py restore  <dll>            # 从 .bak 恢复原版 N
python keygen.py license  --key rsa_private.pem [--email E] [--count N] [--serial S]
                                           # 生成 license.dat
python keygen.py verify   <dll> --key rsa_private.pem [--license license.dat]
                                           # 校验 DLL 中 N 与私钥匹配 + license 签名
python keygen.py patch    <dll> --genkey  # 一键：生成密钥对 + 替换 N + 签发 license
```

### 2.3 关键算法（沿用已验证逻辑，重构命名）

- `build_pattern_instructions()` → `KEY_PATTERN`：74 条 `C7` 指令模板
- `search_pattern_operand_locations()` → `locate_pubkey_operands()`：模式搜索
- `find_xor_key()` / `find_xor_key_backup()` → `locate_xor_key()`：XOR 密钥定位
- `transform()` → `xor_encode_pubkey()`：DER → XOR 编码字节流
- `gen_signature()` / `kg()` → `sign_license()` / `build_license()`：license 签发

### 2.4 备份与安全

- patch 前若存在 `.bak` 则跳过备份（不覆盖原备份）；否则复制为 `<dll>.bak`
- `restore` 用 `.bak` 覆盖回当前 DLL
- 密钥文件默认输出到 `--out-dir`，配合 `.gitignore` 不入库

## 3. 验证方案

1. 副本 DLL 上 `extract` → 与原版 N 比对，确认提取正确
2. `genkey` → `patch` 副本 → `extract` → 确认 N == 新公钥 N
3. `license` → 用 DLL 中新 N 验签 license → 通过
4. `restore` 副本 → `extract` → 确认 N 恢复原版
5. 真实环境：先备份当前 DLL 状态，patch 后用 Binary Ninja 启动验证（GUI 冒烟）

## 4. 与旧实现的兼容

- 旧 `keygen.py` 的 `kg()` / `gen_signature()` 接口保留在 `bn_rsa.py` 中
- 内嵌密钥对不再硬编码在主流程；`--genkey` 一键模式生成全新密钥对
- 依赖保持 `pycryptodome` 单一库
