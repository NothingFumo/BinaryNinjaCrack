# BN headless license 绕过完整方案（v5.3.9434）

## 成果

**完整模拟 BN 的 license 验证**：headless/API 模式可用（GUI 的 version.dll 劫持
之外的第二条路径，不依赖真实验签）。

验证结果：
- `BNIsLicenseValidated = True`
- `binaryninja.load(binaryninja.exe)` → PE view，82113 函数
- MCP backend 完整可用

## 核心发现

license_init（0x1814A3790）在 license 无效时有 **6 处条件跳转**指向
throw 消息构造区（0x14A5340-0x14A5420），抛出 C++ 异常
"License is not valid"（0xE06D7363，经 _CxxThrowException）：

| RVA | 指令 | 检查内容 |
|-----|------|---------|
| 0x14A37F1 | jne 0x14A5340 | 入口检查（_CxxThrowException 间接） |
| 0x14A3B50 | je 0x14A5348 | JSON 解析检查 |
| 0x14A3D50 | jne 0x14A5371 | 280 长度检查 |
| 0x14A446C | je 0x14A539A | 验签结果检查（0x181cbebd0） |
| 0x14A494B | je 0x14A53C3 | 后续检查 |
| 0x14A4B17 | je 0x14A53EB | 后续检查 |

**方案**：6 处全部 NOP → 失败分支自然落入成功路径（0x14A4D53 设置
验证标志 `[rip+0x95a532f]=1`）→ BN 认为 license 有效。

**关键前提**：必须先用 BNSetLicense 提供 license 文本（任意格式即可），
否则 license_init 流程因空对象崩溃（0x80）。

## 实现

`keygen/bn_license_hook.py`：
```python
from bn_license_hook import apply_license_hook
apply_license_hook()   # 自动 BNSetLicense + 6 处 NOP + Validated 恒真
```

仅内存 patch，不改 DLL 文件。MCP 集成：`load_binja_module()` 在
import binaryninja 后立即 apply。

## 验签链（逆向记录）

```
license_init 0x1814A3790
  → 序列化 vtable[0] 0x181D545B0（构造验证对象）
  → 验证引擎 0x181CBEBD0
    → vtable[8] 0x181D0F880（验签入口）
      → [rax+0x40] 0x1D56930（验签核心）
        → 0x181cb7770（参数构建）
        → 0x181d26fd0 → 0x181c4c760（签名解析）
          → 0x181d0d0e0（算法检查 SHA256=1）
          → OpenSSL RSA_verify（0x1C82F70 IAT）
```
