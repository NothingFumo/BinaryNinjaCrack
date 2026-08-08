# -*- coding: utf-8 -*-
"""Binary Ninja binaryninjacore.dll 中 RSA 公钥 N 的定位与替换。

公钥以 XOR 编码的 SPKI DER 存储在 C7 指令序列的 imm32 操作数中：
74 条 `mov dword ptr [reg+disp], imm32` × 4 字节 = 296 字节。
每条指令的 imm32 为 4 字节小端块 XOR 密钥后的编码数据。
"""
from dataclasses import dataclass
from pathlib import Path

#: C7 指令序列模板：None 表示 imm32 操作数位置（可变）
def build_pattern_instructions():
    """构建 74 条 C7 指令的字节模板（0x00..0x124 偏移）。"""
    pattern_instrs = [[0xC7, 0x00, None, None, None, None]]
    offset = 0x04
    while offset <= 0x7C:
        pattern_instrs.append([0xC7, 0x40, offset, None, None, None, None])
        offset += 4
    offset = 0x80
    while offset <= 0xFC:
        pattern_instrs.append(
            [0xC7, 0x80, offset, 0x00, 0x00, 0x00, None, None, None, None]
        )
        offset += 4
    while offset <= 0x124:
        offset_temp = offset - 0x100
        pattern_instrs.append(
            [0xC7, 0x80, offset_temp, 0x01, 0x00, 0x00, None, None, None, None]
        )
        offset += 4
    return pattern_instrs


def locate_operands(binary: bytes, max_gap: int = 32):
    """搜索指令模式，返回 (模式起始偏移, 操作数偏移列表)。

    Returns:
        (start_offset, operand_offsets) 或 (None, None)
    """
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
            operands = [loc for group in operand_groups for loc in group]
            return i, operands
        i += 1
    return None, None


def locate_xor_key(binary: bytes, end_offset: int, search_bytes: int = 150):
    """在模式结束位置之后定位 XOR 密钥。

    识别 `xor reg, imm32`（0x35 /6 或 0x81 /6）或经寄存器传递的 XOR 常量。
    """
    i = end_offset
    max_offset = min(len(binary), i + search_bytes)
    reg_map = {}

    while i < max_offset - 5:
        opcode = binary[i]
        # xor eax, imm32
        if opcode == 0x35 and (binary[i + 1] >> 3) & 7 == 6:
            return int.from_bytes(binary[i + 1 : i + 5], "little")
        # 立即数装载 mov reg, imm32
        if 0xB8 <= opcode <= 0xBF:
            reg = opcode - 0xB8
            reg_map[reg] = int.from_bytes(binary[i + 1 : i + 5], "little")
            i += 5
            continue
        # xor reg, imm32
        if opcode == 0x81:
            modrm = binary[i + 1]
            if (modrm >> 3) & 7 == 6:
                return int.from_bytes(binary[i + 2 : i + 6], "little")
        # xor reg, reg（从已装载寄存器异或）
        if opcode == 0x31:
            modrm = binary[i + 1]
            reg_src = (modrm >> 3) & 7
            if reg_src in reg_map:
                return reg_map[reg_src]
        i += 1
    return None


def xor_encode_pubkey(pubkey_der: bytes, length: int, xor_key: int) -> bytes:
    """将公钥 DER 编码为 XOR 混淆的字节流（长度固定为 296）。"""
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
    """XOR 编码流解码回 DER 字节流。"""
    return b"".join(
        (int.from_bytes(encoded[i : i + 4], "little") ^ xor_key).to_bytes(4, "little")
        for i in range(0, len(encoded), 4)
    )


@dataclass
class PubkeyLocation:
    """定位结果：模式起始、操作数偏移、XOR 密钥、编码长度。"""

    start_offset: int
    operand_offsets: list
    xor_key: int
    length: int

    @property
    def end_offset(self) -> int:
        return self.operand_offsets[-1] + 1


def locate_pubkey(binary: bytes, max_gap: int = 32) -> PubkeyLocation:
    """在 DLL 字节流中定位公钥存储区。

    Raises:
        ValueError: 模式未找到或 XOR 密钥未找到
    """
    start, operands = locate_operands(binary, max_gap)
    if start is None:
        raise ValueError("C7 指令模式未找到，DLL 版本可能不兼容")
    length = len(operands)
    end = operands[-1] + 1
    xor_key = locate_xor_key(binary, end)
    if xor_key is None:
        raise ValueError("XOR 密钥定位失败")
    return PubkeyLocation(start, operands, xor_key, length)


def extract_pubkey_der(binary: bytes) -> bytes:
    """从 DLL 字节流提取解码后的公钥 DER。

    Returns:
        SPKI DER 字节（解码流，可能含尾部 padding 字节）
    """
    loc = locate_pubkey(binary)
    encoded = bytes(binary[off] for off in loc.operand_offsets)
    return xor_decode_pubkey(encoded, loc.xor_key)


def make_backup(dll_path: str) -> Path:
    """patch 前备份 DLL。已存在 .bak 则不重复备份。

    Returns:
        备份文件路径
    """
    dll = Path(dll_path)
    backup = dll.with_suffix(dll.suffix + ".bak")
    if not backup.exists():
        backup.write_bytes(dll.read_bytes())
    return backup


def patch_pubkey(dll_path: str, pubkey_der: bytes, backup: bool = True) -> PubkeyLocation:
    """将新公钥 DER 写入 DLL 的 N 存储区。

    Args:
        dll_path: binaryninjacore.dll 路径
        pubkey_der: SPKI DER 公钥
        backup: 是否先备份为 .bak

    Returns:
        定位信息（含长度，可据此验证）
    """
    dll = Path(dll_path)
    if backup:
        make_backup(dll_path)
    data = bytearray(dll.read_bytes())
    loc = locate_pubkey(bytes(data))
    if len(pubkey_der) + 2 > loc.length:
        raise ValueError(
            f"公钥 DER 过长：{len(pubkey_der)} 字节，存储区仅 {loc.length} 字节"
        )
    # DER + 尾部 padding（保持存储区长度不变）
    encoded = xor_encode_pubkey(pubkey_der, loc.length, loc.xor_key)
    for off, byte in zip(loc.operand_offsets, encoded):
        data[off] = byte
    dll.write_bytes(bytes(data))
    return loc


def restore_pubkey(dll_path: str) -> Path:
    """从 .bak 恢复原版 DLL。

    Returns:
        备份文件路径
    """
    dll = Path(dll_path)
    backup = dll.with_suffix(dll.suffix + ".bak")
    if not backup.exists():
        raise FileNotFoundError(f"备份文件不存在：{backup}")
    dll.write_bytes(backup.read_bytes())
    return backup
