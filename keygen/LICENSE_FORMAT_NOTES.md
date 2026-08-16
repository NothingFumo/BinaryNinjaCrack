# Binary Ninja v5.3.9434 license 格式逆向报告（未完成）

## 已确认（frida 动态验证）

| 项 | 值 | 证据 |
|---|---|---|
| 签名算法 | SHA-256（PKCS1） | 验证对象含 "SHA-256" 字符串 |
| data 字段 | 280B = 256B 随机 + RC4(MD5(随机), 24B magic) | Count=999 解析成功 |
| expiresEpoch | 必须存在 | 缺失时解析失败 |
| signature | 280B = 24B 前缀 + 256B PKCS1 签名 | 280 长度检查 0x118 |
| 消息分隔符 | '.' 连接（frida 捕获） | 0x181d544d0 输入 467B |
| 验签链 | 0x181D0F880 → 0x181D560C0 → 0x181CEB8A0 → 0x180A409B0 → 0x181C82F70(OpenSSL) | vtable 追踪 |

## 未解决

- **验签消息** = 19 字符 base64（13B），由 data 派生，非标准哈希（MD5/SHA1/SHA256/CRC32 均不匹配）
- **data 字段内部结构**：BN 反序列化 data 时访问 [obj+0x70] 崩溃 → data 编码格式未复刻
- **验证对象构造**：0x181D545B0 虚函数框架，3+ 层抽象

## 结论

keygen 生成的 license 能被 BN 解析（Count=999），但 data 字段的
内部结构不符合 BN 预期（反序列化崩溃），导致验签无法完成。
彻底解决需逆向 BN 的 data 序列化框架（不可控工作量）。
