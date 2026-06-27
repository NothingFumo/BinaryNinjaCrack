# RSA 注册机

生成 RSA 密钥对 + license.dat，用于配合 RSA 公钥替换方案。

## 原理

Binary Ninja 使用 RSA 签名验证 license.dat：

```
license.dat 内容 → SHA256 哈希 → RSA 私钥签名 → 签名数据
                                                    ↓
程序读取 license.dat → RSA 公钥验签 → 通过/失败
```

通过替换 DLL 中的 RSA 公钥 N，用自定义私钥签名，即可通过验证。

## 使用

```bash
pip install pycryptodome
python keygen.py
```

## 生成文件

| 文件 | 说明 |
|------|------|
| `rsa_private.pem` | RSA 私钥（签名用） |
| `rsa_public.pem` | RSA 公钥（验签用） |
| `xor_key.bin` | XOR 编码密钥 |
| `encoded_key.bin` | 编码后的 RSA N |
| `license.dat` | 许可证文件 |

## 配合 DLL 劫持使用

```bash
# 1. 生成密钥
python keygen.py

# 2. 补丁 binaryninjacore.dll 中的 RSA N
python bn_keygen.py --patch

# 3. 复制 license.dat 到安装目录
cp license.dat "D:\BinaryNinja\"
```

## 注意事项

- 需要 `pycryptodome` 库：`pip install pycryptodome`
- RSA 密钥长度默认 4096 位
- 生成的 license.dat 需配合 RSA N 补丁使用
