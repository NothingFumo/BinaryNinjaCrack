# -*- coding: utf-8 -*-
"""Binary Ninja 授权生成器（keygen）。

适用版本：v5.3.9434，其它版本自测。
使用说明：仅供测试、需要修改 RSA N —— 必须将 DLL 中内嵌的
原版公钥 N 替换为自定义密钥对的公钥 N，license 才能验签通过。

子命令：
  extract  提取 DLL 中当前公钥 N
  genkey   生成新 RSA 密钥对
  patch    用指定公钥替换 DLL 中 N（自动备份 .bak）
  restore  从 .bak 恢复原版 DLL
  license  生成 license.dat
  verify   校验 DLL 中 N 与私钥匹配及 license 签名
"""
import argparse
import sys
from pathlib import Path

from Crypto.PublicKey import RSA

import bn_patch
import bn_rsa

KEY_BITS = 2048


def cmd_extract(args):
    data = Path(args.dll).read_bytes()
    der = bn_patch.extract_pubkey_der(data)
    key = RSA.import_key(der[:294])
    n_bytes = key.n.to_bytes((key.size_in_bits() + 7) // 8, "big")
    print(f"DLL:       {args.dll}")
    print(f"位长:      {key.size_in_bits()} bit (e=0x{key.e:X})")
    print(f"N (hex):   {n_bytes.hex()}")
    if args.out:
        Path(args.out).write_bytes(der[:294])
        print(f"DER 已写入: {args.out}")
    return 0


def cmd_genkey(args):
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    priv, pub = bn_rsa.generate_keypair(KEY_BITS)
    priv_path = out_dir / "rsa_private.pem"
    pub_path = out_dir / "rsa_public.pem"
    priv_path.write_text(priv.export_key().decode())
    pub_path.write_text(pub.export_key().decode())
    print(f"私钥: {priv_path}")
    print(f"公钥: {pub_path}")
    return 0


def cmd_patch(args):
    pub_data = Path(args.key).read_bytes()
    key = RSA.import_key(pub_data)
    if key.size_in_bits() != KEY_BITS:
        print(f"警告: 密钥位长 {key.size_in_bits()}，目标版本为 {KEY_BITS}", file=sys.stderr)
    der = bn_rsa.public_key_to_der(key)
    if len(der) + 2 > 0x128:
        raise ValueError(f"公钥 DER 过长: {len(der)} 字节 > 存储区 {0x128 - 2} 字节")
    loc = bn_patch.patch_pubkey(args.dll, der, backup=not args.no_backup)
    # 验证写回
    data = Path(args.dll).read_bytes()
    back = bn_patch.extract_pubkey_der(data)
    ok = back[: len(der)] == der
    n_bytes = key.n.to_bytes(256, "big")
    print(f"模式起始:  0x{loc.start_offset:X}")
    print(f"XOR 密钥:  0x{loc.xor_key:08X}")
    print(f"写入字节:  {loc.length}")
    print(f"新 N:      {n_bytes.hex()}")
    print(f"写回校验:  {'通过' if ok else '失败!'}")
    print("下一步: 用同一私钥生成 license 并放入安装目录")
    return 0 if ok else 1


def cmd_restore(args):
    backup = bn_patch.restore_pubkey(args.dll)
    print(f"已从 {backup} 恢复 {args.dll}")
    return 0


def cmd_license(args):
    key_data = Path(args.key).read_bytes()
    priv = RSA.import_key(key_data)
    text = bn_rsa.generate_license(
        email=args.email,
        count=args.count,
        serial_hexstr=args.serial,
        product=args.product,
        lic_type=args.type,
        private_key=priv,
    )
    out = args.out or "license.dat"
    Path(out).write_text(text, encoding="utf-8")
    print(f"license 已生成: {out}")
    return 0


def cmd_verify(args):
    der = bn_patch.extract_pubkey_der(Path(args.dll).read_bytes())
    key = RSA.import_key(der[:294])
    n_hex = key.n.to_bytes(256, "big").hex()
    priv_data = Path(args.key).read_bytes()
    priv = RSA.import_key(priv_data)
    match = key.n == priv.n
    print(f"DLL 中 N:    {n_hex}")
    print(f"私钥匹配:    {'是' if match else '否'}")
    if args.license:
        lic = bn_rsa.license_from_text(Path(args.license).read_text(encoding="utf-8"))
        from Crypto.Signature import pkcs1_15
        import base64

        ok = bn_rsa.verify_license(
            lic, key, base64.b64decode(lic["signature"])
        )
        print(f"license 验签: {'通过' if ok else '失败'}")
    return 0 if match else 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="keygen",
        description="Binary Ninja 授权生成器（需要修改 RSA N）",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("extract", help="提取 DLL 中当前公钥 N")
    p.add_argument("dll", help="binaryninjacore.dll 路径")
    p.add_argument("--out", help="输出 DER 到文件")
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("genkey", help="生成新 RSA 密钥对")
    p.add_argument("--out-dir", default=".", help="输出目录（默认当前目录）")
    p.set_defaults(func=cmd_genkey)

    p = sub.add_parser("patch", help="用公钥替换 DLL 中 N")
    p.add_argument("dll", help="binaryninjacore.dll 路径")
    p.add_argument("--key", required=True, help="公钥 PEM 文件")
    p.add_argument("--no-backup", action="store_true", help="不备份 .bak")
    p.set_defaults(func=cmd_patch)

    p = sub.add_parser("restore", help="从 .bak 恢复原版 DLL")
    p.add_argument("dll", help="binaryninjacore.dll 路径")
    p.set_defaults(func=cmd_restore)

    p = sub.add_parser("license", help="生成 license.dat")
    p.add_argument("--key", required=True, help="私钥 PEM 文件")
    p.add_argument("--email", default="hi@binja.com", help="邮箱")
    p.add_argument("--count", type=int, default=32, help="授权数量")
    p.add_argument("--serial", help="序列号（hex，默认随机）")
    p.add_argument("--product", default="Binary Ninja Personal", help="产品名")
    p.add_argument("--type", default="User", help="许可类型")
    p.add_argument("--out", help="输出文件（默认 license.dat）")
    p.set_defaults(func=cmd_license)

    p = sub.add_parser("verify", help="校验 DLL 中 N 与私钥匹配")
    p.add_argument("dll", help="binaryninjacore.dll 路径")
    p.add_argument("--key", required=True, help="私钥 PEM 文件")
    p.add_argument("--license", help="license.dat 路径（可选，额外验签）")
    p.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, FileNotFoundError) as e:
        print(f"错误: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
