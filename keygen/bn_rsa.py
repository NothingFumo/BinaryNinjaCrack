# -*- coding: utf-8 -*-
"""Binary Ninja RSA 密钥与许可证模块。

提供密钥对生成、SPKI DER 编码、license.dat 签发与验证。
适用版本：v5.3.9434，其它版本自测。
"""
import base64
import hashlib
import json
import random
from datetime import datetime, timezone

from Crypto.Cipher import ARC4
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

#: license 的 data 字段中加密的固定 magic（8 字节）
_DATA_MAGIC = bytes.fromhex("9C2AAA09A4E2252B0BA125DB1E1CD272207D97CCA8446899")


def generate_keypair(bits: int = 2048):
    """生成新的 RSA 密钥对。

    Returns:
        (private_key, public_key): Crypto.PublicKey.RSA 对象
    """
    key = RSA.generate(bits)
    return key, key.publickey()


def public_key_to_der(key) -> bytes:
    """公钥导出为 SPKI DER（2048 位时 294 字节）。"""
    return key.export_key(format="DER")


def _get_time_str() -> str:
    """ISO8601 UTC 时间字符串（毫秒精度）。"""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _gen_licdata() -> str:
    """生成 license 的 data 字段。

    结构：0x100 字节随机数（其 MD5 作为 RC4 密钥）加密固定 8 字节 magic，
    整体 base64。
    """
    randdata = random.randbytes(0x100)
    k = hashlib.md5(randdata).digest()
    encdta = ARC4.new(key=k).encrypt(_DATA_MAGIC)
    return base64.standard_b64encode(randdata + encdta).decode()


def _build_license_message(lic: dict) -> bytes:
    """按程序验证逻辑拼接签名消息：字段以 \\x00 连接。"""
    return "\x00".join(
        (
            lic["product"],
            lic["email"],
            lic["serial"],
            lic["created"],
            lic["type"],
            str(lic["count"]),
            lic["data"],
        )
    ).encode()


def build_license(
    email: str,
    count: int = 32,
    serial_hexstr: str = None,
    product: str = "Binary Ninja Personal",
    lic_type: str = "User",
) -> dict:
    """构建未签名的 license 数据字典。"""
    if serial_hexstr is None:
        serial_hexstr = random.randbytes(0x10).hex()
    return {
        "product": product,
        "email": email,
        "serial": serial_hexstr,
        "created": _get_time_str(),
        "type": lic_type,
        "count": count,
        "data": _gen_licdata(),
    }


def sign_license(lic: dict, private_key) -> bytes:
    """用私钥对 license 内容签名，返回 PKCS#1 v1.5 原始签名字节。"""
    msg = _build_license_message(lic)
    return pkcs1_15.new(private_key).sign(SHA256.new(msg))


def verify_license(lic: dict, public_key, signature: bytes) -> bool:
    """用公钥验证 license 签名。签名错误返回 False。"""
    msg = _build_license_message(lic)
    try:
        pkcs1_15.new(public_key).verify(SHA256.new(msg), signature)
        return True
    except (ValueError, TypeError):
        return False


def license_to_text(lic: dict, signature: bytes) -> str:
    """输出 license.dat 文本（JSON 数组格式，与原程序解析一致）。"""
    lic = dict(lic)
    lic["signature"] = base64.standard_b64encode(signature).decode()
    return "[\n%s\n]" % json.dumps(lic, indent=0)


def license_from_text(text: str) -> dict:
    """解析 license.dat 文本为数据字典。"""
    return json.loads(text)[0]


def generate_license(
    email: str,
    count: int = 32,
    serial_hexstr: str = None,
    product: str = "Binary Ninja Personal",
    lic_type: str = "User",
    private_key=None,
) -> str:
    """一键生成 license.dat 文本。

    Args:
        private_key: 私钥（RSA 对象或 PEM 字节/字符串/路径）
    """
    if isinstance(private_key, (str, bytes)):
        private_key = RSA.import_key(private_key)
    lic = build_license(email, count, serial_hexstr, product, lic_type)
    sig = sign_license(lic, private_key)
    return license_to_text(lic, sig)
