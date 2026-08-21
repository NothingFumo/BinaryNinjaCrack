# -*- coding: utf-8 -*-
"""Binary Ninja 授权生成器（单文件版）。

适用版本：v5.3.9434，其它版本自测。
使用说明：仅供测试、需要修改 RSA N —— 必须将 DLL 中内嵌的原版
公钥 N 替换为自定义密钥对的公钥 N，license 才能验签通过。

用法（与 exe-patch / deploy.py 风格一致）:
  cd keygen
  python keygen.py D:\\BinaryNinja                # 部署：一键 生成密钥→patch→license
  python keygen.py D:\\BinaryNinja --restore     # 恢复
  python keygen.py D:\\BinaryNinja --dry-run     # 仅分析

  # 将 keygen.py 放入安装目录后直接运行：
  cd D:\\BinaryNinja
  python keygen.py                               # 自动查找当前目录 DLL
  python keygen.py --restore                     # 恢复

一键流程（默认）:
  1. 生成 RSA-2048 密钥对（已存在则复用，存放于工作目录）
  2. 定位并替换 DLL 中的公钥 N（自动备份 .bak）
  3. 生成 license.dat 到 DLL 所在目录

辅助:
  --extract  仅提取 DLL 当前 N（不写入）
  --verify   校验 DLL 中 N 与私钥匹配 + license 验签
"""
import argparse
import base64
import hashlib
import json
import random
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from Crypto.Cipher import ARC4
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

KEY_BITS = 2048              # RSA 密钥长度
PATCH_LENGTH = 0x128         # 公钥存储区长度（296 字节 = DER 294B + 2B padding）
DATA_MAGIC = bytes.fromhex("9C2AAA09A4E2252B0BA125DB1E1CD272207D97CCA8446899")
DEFAULT_EMAIL = "hi@binja.com"
DEFAULT_COUNT = 999

# ---------------------------------------------------------------------------
# 模块 A：DLL 中 RSA 公钥 N 的定位与替换
# 公钥以 XOR 编码的 SPKI DER 存储在 C7 指令序列的 imm32 操作数中：
# 74 条 `mov dword ptr [reg+disp], imm32` × 4 字节 = 296 字节。
# ---------------------------------------------------------------------------


def build_pattern_instructions():
    """构建 74 条 C7 指令的字节模板（0x00..0x124 偏移）。"""
    pattern = [[0xC7, 0x00, None, None, None, None]]
    offset = 0x04
    while offset <= 0x7C:
        pattern.append([0xC7, 0x40, offset, None, None, None, None])
        offset += 4
    offset = 0x80
    while offset <= 0xFC:
        pattern.append(
            [0xC7, 0x80, offset, 0x00, 0x00, 0x00, None, None, None, None]
        )
        offset += 4
    while offset <= 0x124:
        pattern.append(
            [0xC7, 0x80, offset - 0x100, 0x01, 0x00, 0x00, None, None, None, None]
        )
        offset += 4
    return pattern


def locate_operands(binary: bytes, max_gap: int = 32):
    """搜索指令模式，返回 (模式起始偏移, 操作数偏移列表) 或 (None, None)。"""
    pattern = build_pattern_instructions()
    n = len(binary)
    first = pattern[0]
    plen = len(first)

    i = 0
    while i <= n - plen:
        operand_groups = []
        match = True
        instr_locs = []
        for j in range(plen):
            if first[j] is None:
                instr_locs.append(i + j)
            elif binary[i + j] != first[j]:
                match = False
                break
        if not match:
            i += 1
            continue
        operand_groups.append(instr_locs)
        last_pos = i

        for instr in pattern[1:]:
            instr_len = len(instr)
            found = False
            search_limit = min(last_pos + 1 + max_gap, n - instr_len + 1)
            for k in range(last_pos + 1, search_limit):
                sub_match = True
                instr_locs = []
                for l in range(instr_len):
                    if instr[l] is None:
                        instr_locs.append(k + l)
                    elif binary[k + l] != instr[l]:
                        sub_match = False
                        break
                if sub_match:
                    operand_groups.append(instr_locs)
                    last_pos = k
                    found = True
                    break
            if not found:
                match = False
                break
        if match:
            return i, [loc for group in operand_groups for loc in group]
        i += 1
    return None, None


def locate_xor_key(binary: bytes, end_offset: int, search_bytes: int = 150):
    """在模式结束位置之后定位 XOR 密钥（xor reg, imm32 或经寄存器传递）。"""
    i = end_offset
    max_offset = min(len(binary), i + search_bytes)
    reg_map = {}

    while i < max_offset - 5:
        opcode = binary[i]
        if opcode == 0x35 and (binary[i + 1] >> 3) & 7 == 6:
            return int.from_bytes(binary[i + 1 : i + 5], "little")
        if 0xB8 <= opcode <= 0xBF:  # mov reg, imm32
            reg_map[opcode - 0xB8] = int.from_bytes(binary[i + 1 : i + 5], "little")
            i += 5
            continue
        if opcode == 0x81 and (binary[i + 1] >> 3) & 7 == 6:  # xor reg, imm32
            return int.from_bytes(binary[i + 2 : i + 6], "little")
        if opcode == 0x31:  # xor reg, reg
            reg_src = (binary[i + 1] >> 3) & 7
            if reg_src in reg_map:
                return reg_map[reg_src]
        i += 1
    return None


def xor_encode_pubkey(pubkey_der: bytes, length: int, xor_key: int) -> bytes:
    """DER → XOR 编码字节流（固定长度）。"""
    table = [
        int.from_bytes(pubkey_der[i : i + 4], "little")
        for i in range(0, len(pubkey_der), 4)
    ]
    dst = bytearray(length)
    for i in range(length):
        rax = i >> 2
        edx = table[rax] ^ xor_key
        shift = (i & 3) << 3
        dst[i] = (edx >> shift) & 0xFF
    return bytes(dst)


def xor_decode_pubkey(encoded: bytes, xor_key: int) -> bytes:
    """XOR 编码流 → DER 字节流。"""
    return b"".join(
        (int.from_bytes(encoded[i : i + 4], "little") ^ xor_key).to_bytes(4, "little")
        for i in range(0, len(encoded), 4)
    )


@dataclass
class PubkeyLocation:
    start_offset: int
    operand_offsets: list
    xor_key: int
    length: int


def locate_pubkey(binary: bytes, max_gap: int = 32) -> PubkeyLocation:
    """在 DLL 字节流中定位公钥存储区。"""
    start, operands = locate_operands(binary, max_gap)
    if start is None:
        raise ValueError("C7 指令模式未找到，DLL 版本可能不兼容")
    end = operands[-1] + 1
    xor_key = locate_xor_key(binary, end)
    if xor_key is None:
        raise ValueError("XOR 密钥定位失败")
    return PubkeyLocation(start, operands, xor_key, len(operands))


def extract_pubkey_der(binary: bytes) -> bytes:
    """从 DLL 提取解码后的公钥 DER（294 字节）。"""
    loc = locate_pubkey(binary)
    encoded = bytes(binary[off] for off in loc.operand_offsets)
    return xor_decode_pubkey(encoded, loc.xor_key)[:294]


def _replace_occupied(dll: Path, write_data: bytes) -> None:
    """DLL 被进程占用时的替换写回。

    将原文件重命名为 <dll>.locked（占用进程继续持有旧句柄），再写入新内容。
    自动清理上一次部署遗留的 .locked 残留（若已被释放）；若残留仍被占用
    （无法删除），则给出明确指引。
    """
    import os

    locked = dll.with_name(dll.name + ".locked")
    try:
        if locked.exists():
            locked.unlink()  # 清理上次部署残留（进程已退出、句柄已释放）
    except PermissionError:
        raise PermissionError(
            f"DLL 与 {locked.name} 均被进程占用，无法替换；"
            f"请先停止占用进程（headless MCP / Binary Ninja GUI）后重试"
        )
    os.rename(dll, locked)
    dll.write_bytes(write_data)
    print(f"提示: DLL 被进程占用，原文件已重命名为 {locked.name}")


def patch_pubkey(dll_path, pubkey_der: bytes, backup: bool = True) -> PubkeyLocation:
    """将新公钥 DER 写入 DLL 的 N 存储区。

    若 DLL 被进程占用（共享冲突，如 headless MCP 加载），自动将原文件
    重命名为 <dll>.locked（占用进程继续持有旧句柄），再从内存写回新文件。
    """
    dll = Path(dll_path)
    if backup:
        backup_path = dll.with_suffix(dll.suffix + ".bak")
        if not backup_path.exists():
            backup_path.write_bytes(dll.read_bytes())
    data = bytearray(dll.read_bytes())
    loc = locate_pubkey(bytes(data))
    if len(pubkey_der) + 2 > loc.length:
        raise ValueError(
            f"公钥 DER 过长：{len(pubkey_der)} 字节，存储区仅 {loc.length} 字节"
        )
    encoded = xor_encode_pubkey(pubkey_der, loc.length, loc.xor_key)
    for off, byte in zip(loc.operand_offsets, encoded):
        data[off] = byte
    try:
        dll.write_bytes(bytes(data))
    except PermissionError:
        _replace_occupied(dll, bytes(data))
    return loc


def restore_pubkey(dll_path) -> Path:
    """从 .bak 恢复原版 DLL（被占用时自动重命名替换）。"""
    dll = Path(dll_path)
    backup = dll.with_suffix(dll.suffix + ".bak")
    if not backup.exists():
        raise FileNotFoundError(f"备份文件不存在：{backup}")
    data = backup.read_bytes()
    try:
        dll.write_bytes(data)
    except PermissionError:
        _replace_occupied(dll, data)
    return backup


# ---------------------------------------------------------------------------
# 模块 B：RSA 密钥与 license 签发
# license 验签消息 = 7 字段按序以 \x00 连接，SHA256 + PKCS#1 v1.5 签名。
# 注：实验确认 SHA256 版 license 可被解析（Count=999），MD5 版解析失败。
# ---------------------------------------------------------------------------


def generate_keypair(bits: int = KEY_BITS):
    key = RSA.generate(bits)
    return key, key.publickey()


def get_time_str() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def gen_licdata() -> str:
    """data 字段：0x100 随机字节（MD5 作 RC4 密钥）加密固定 magic，base64。"""
    randdata = random.randbytes(0x100)
    encdta = ARC4.new(key=hashlib.md5(randdata).digest()).encrypt(DATA_MAGIC)
    return base64.standard_b64encode(randdata + encdta).decode()


def build_license_message(lic: dict) -> bytes:
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


def generate_license(
    email: str,
    count: int = DEFAULT_COUNT,
    serial_hexstr: str = None,
    product: str = "Binary Ninja Personal",
    lic_type: str = "User",
    private_key=None,
) -> str:
    """生成 license.dat 文本（JSON 数组格式）。"""
    if serial_hexstr is None:
        serial_hexstr = random.randbytes(0x10).hex()
    lic = {
        "product": product,
        "email": email,
        "serial": serial_hexstr,
        "created": get_time_str(),
        "type": lic_type,
        "count": count,
        "data": gen_licdata(),
    }
    sig = pkcs1_15.new(private_key).sign(SHA256.new(build_license_message(lic)))
    lic["signature"] = base64.standard_b64encode(sig).decode()
    return "[\n%s\n]" % json.dumps(lic, indent=0)


def verify_license(lic: dict, public_key, signature: bytes) -> bool:
    try:
        pkcs1_15.new(public_key).verify(
            SHA256.new(build_license_message(lic)), signature
        )
        return True
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# 模块 C：CLI（扁平参数，与 exe-patch 风格一致）
# ---------------------------------------------------------------------------


def default_workdir() -> Path:
    """默认工作目录 = 脚本所在目录。"""
    return Path(__file__).resolve().parent


def key_paths(workdir: Path):
    return workdir / "rsa_private.pem", workdir / "rsa_public.pem"


def load_or_create_keypair(workdir: Path):
    """加载工作目录中的密钥对；不存在则生成。"""
    priv_path, pub_path = key_paths(workdir)
    if priv_path.exists() and pub_path.exists():
        priv = RSA.import_key(priv_path.read_bytes())
        return priv, priv.publickey(), False
    priv, pub = generate_keypair()
    priv_path.write_text(priv.export_key().decode())
    pub_path.write_text(pub.export_key().decode())
    print(f"已生成密钥对: {priv_path} / {pub_path}")
    return priv, pub, True


def find_default_dll() -> Path:
    """默认 DLL：当前目录或脚本目录下的 binaryninjacore.dll。"""
    for base in (Path.cwd(), Path(__file__).resolve().parent):
        cand = base / "binaryninjacore.dll"
        if cand.exists():
            return cand
    raise FileNotFoundError(
        "未找到 binaryninjacore.dll，请指定安装目录（如 python keygen.py D:/BinaryNinja）"
    )


def resolve_dll(target: str = None) -> Path:
    """解析目标为 binaryninjacore.dll 路径。

    支持三种方式：
      1. 位置参数指定安装目录（如 D:/BinaryNinja）
      2. 位置参数直接指定 DLL 文件
      3. 无参数：自动查找当前目录 / 脚本目录
    """
    if target:
        p = Path(target)
        if p.is_dir():
            cand = p / "binaryninjacore.dll"
            if not cand.exists():
                raise FileNotFoundError(f"目录中未找到 {cand}")
            return cand
        return p
    return find_default_dll()


def hosts_path() -> Path:
    return Path(r"C:\Windows\System32\drivers\etc\hosts")


def block_update_server() -> int:
    """屏蔽更新/认证服务器：hosts 将 api.binary.ninja 指向 127.0.0.1。

    目的：keygen 的 license 只能通过本地验证（DLL 内公钥已替换），
    更新检查用官方公钥验签必然失败（"Update authentication failed:
    License not found"）。屏蔽后更新检查静默失败，不再弹错。
    """
    lines = [
        "# Block Binary Ninja update/license auth (added by keygen)",
        "0.0.0.0 api.binary.ninja",
        "127.0.0.1 api.binary.ninja",
    ]
    hp = hosts_path()
    content = hp.read_text(encoding="utf-8", errors="ignore")
    if "api.binary.ninja" in content:
        print("更新服务器已在屏蔽状态（hosts 中已存在 api.binary.ninja）")
        return 0
    with open(hp, "a", encoding="utf-8") as f:
        f.write("\n" + "\n".join(lines) + "\n")
    print("已屏蔽更新服务器: api.binary.ninja -> 127.0.0.1")
    return 0


def unblock_update_server() -> int:
    """从 hosts 移除屏蔽条目，恢复更新检查。"""
    hp = hosts_path()
    content = hp.read_text(encoding="utf-8", errors="ignore")
    if "api.binary.ninja" not in content:
        print("未发现屏蔽条目（hosts 中无 api.binary.ninja）")
        return 0
    kept = [
        ln for ln in content.splitlines()
        if "api.binary.ninja" not in ln
        and "Block Binary Ninja update" not in ln
    ]
    hp.write_text("\n".join(kept) + "\n", encoding="utf-8")
    print("已取消屏蔽，更新服务器恢复")
    return 0


def main():
    ap = argparse.ArgumentParser(
        prog="keygen",
        description="Binary Ninja 授权生成器（单文件，需要修改 RSA N）",
    )
    ap.add_argument("target", nargs="?", default=None,
                    help="Binary Ninja 安装目录或 binaryninjacore.dll 路径（省略时自动查找）")
    ap.add_argument("--dll", default=None, help="binaryninjacore.dll 路径（与位置参数等价）")
    ap.add_argument("--work-dir", default=str(default_workdir()),
                    help="工作目录（密钥存放，默认脚本所在目录）")
    ap.add_argument("--license-dir", default=None,
                    help="license 输出目录（默认 DLL 所在目录）")
    ap.add_argument("--restore", action="store_true", help="从备份恢复原版 DLL")
    ap.add_argument("--dry-run", action="store_true", help="仅分析，不写入")
    ap.add_argument("--extract", action="store_true", help="仅提取 DLL 当前 N")
    ap.add_argument("--verify", action="store_true", help="校验 DLL 中 N 与私钥匹配")
    ap.add_argument("--email", default=DEFAULT_EMAIL, help="license 邮箱")
    ap.add_argument("--count", type=int, default=DEFAULT_COUNT, help="license 授权数量")
    ap.add_argument("--serial", default=None, help="license 序列号（hex）")
    ap.add_argument("--no-backup", action="store_true", help="patch 前不备份 .bak")
    ap.add_argument("--block-updates", action="store_true",
                    help="屏蔽更新服务器（hosts 添加 api.binary.ninja，避免 license 认证报错）")
    ap.add_argument("--unblock-updates", action="store_true",
                    help="取消屏蔽更新服务器（从 hosts 移除）")
    args = ap.parse_args()

    try:
        if args.block_updates:
            return block_update_server()
        if args.unblock_updates:
            return unblock_update_server()

        dll = resolve_dll(args.target or args.dll)

        if args.restore:
            backup = restore_pubkey(dll)
            print(f"已从 {backup} 恢复 {dll}")
            return 0

        if args.extract:
            der = extract_pubkey_der(dll.read_bytes())
            key = RSA.import_key(der)
            print(f"DLL:      {dll}")
            print(f"位长:     {key.size_in_bits()} bit (e=0x{key.e:X})")
            print(f"N (hex):  {key.n.to_bytes(256, 'big').hex()}")
            return 0

        if args.verify:
            der = extract_pubkey_der(dll.read_bytes())
            key = RSA.import_key(der)
            priv_path, _ = key_paths(Path(args.work_dir))
            if not priv_path.exists():
                print(f"错误: 工作目录中无私钥 {priv_path}，先运行一键生成", file=sys.stderr)
                return 1
            priv = RSA.import_key(priv_path.read_bytes())
            match = key.n == priv.n
            print(f"DLL 中 N:  {key.n.to_bytes(256, 'big').hex()}")
            print(f"私钥匹配:  {'是' if match else '否'}")
            return 0 if match else 1

        # 一键：生成密钥 → patch → license
        workdir = Path(args.work_dir)
        workdir.mkdir(parents=True, exist_ok=True)
        priv, pub, created = load_or_create_keypair(workdir)
        der = pub.export_key(format="DER")

        loc = locate_pubkey(dll.read_bytes())
        print(f"DLL:        {dll}")
        print(f"模式起始:   0x{loc.start_offset:X}")
        print(f"XOR 密钥:   0x{loc.xor_key:08X}")
        print(f"当前 N:     {RSA.import_key(extract_pubkey_der(dll.read_bytes())).n.to_bytes(256, 'big').hex()}")
        print(f"新 N:       {pub.n.to_bytes(256, 'big').hex()}")

        if not args.dry_run:
            patch_pubkey(dll, der, backup=not args.no_backup)
            # 写回自校验
            back = extract_pubkey_der(dll.read_bytes())
            if back != der:
                raise RuntimeError("写回校验失败，DLL 中的 N 与公钥不一致")
            print("写回校验:   通过")

            lic_dir = Path(args.license_dir) if args.license_dir else dll.parent
            lic_dir.mkdir(parents=True, exist_ok=True)
            lic_path = lic_dir / "license.dat"
            lic_path.write_text(
                generate_license(
                    email=args.email,
                    count=args.count,
                    serial_hexstr=args.serial,
                    private_key=priv,
                ),
                encoding="utf-8",
            )
            print(f"license:    {lic_path}")
            print("完成：将 license.dat 放入 Binary Ninja 安装目录后启动即可")
        return 0
    except (ValueError, FileNotFoundError, OSError) as e:
        print(f"错误: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
