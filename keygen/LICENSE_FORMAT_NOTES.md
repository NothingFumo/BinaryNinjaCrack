# BN 验签消息结构最终逆向结论（v5.3.9434）

## 消息结构（frida 运行时捕获）

```
280B 验签消息 =
  "\x00" + "MSA3(SHA-256)"   ← 算法标识（EMSA3 = PKCS#1 v1.5 + SHA-256）
  + 指针区（对象序列化，含堆地址）
  + "AuthcAMD" + 13字节认证数据
```

- 算法字符串 `EMSA3(SHA-256)` 位于 DLL 0x6D532E8（字符串区）
- `AuthcAMD` = 运行时拼接的认证库标识
- 13 字节认证数据由 license 的 data 字段派生（确定性），**非标准哈希**

## 验证链（Stalker + vtable 追踪）

```
BNInitPlugins
  → license_init (0x1814A3790)
    → 序列化 vtable[0] (0x181D545B0)     构造 467B 字段消息（. 连接）
    → 验证对象构造 (0x181d544d0)
    → 验证引擎 (0x181CBEBD0)
      → vtable[8] (0x181D0F880)          验签入口
        → [rax+0x40] (0x1D56930)         验签核心
          → 0x181cb7770                  参数构建
          → 0x181d26fd0 → 0x181c4c760   签名解析
            → 0x181d0d0e0                算法检查 (SHA256=1)
            → OpenSSL RSA_verify (0x1C82F70 IAT)
```

## 结论

BN 5.3.9434 的验签消息是**运行时构造的对象序列化**（含堆指针 +
`AuthcAMD` 自定义认证数据），**非纯数据格式**。keygen 无法构造
匹配的消息 → headless/MCP 真实验签不可绕过。

GUI 方案（version.dll 劫持）不依赖真实验签，仍可用。
