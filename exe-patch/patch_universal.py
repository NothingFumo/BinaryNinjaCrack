#!/usr/bin/env python3
"""
Binary Ninja EXE 通用许可证绕过补丁 (v2)
==========================================
通过许可证错误字符串锚点动态定位 JNE 补丁位置，兼容多版本。

原理:
  1. 搜索许可证错误字符串 (如 "The provided license is invalid")
  2. 找到引用该字符串的 LEA 指令
  3. 从 LEA 向前搜索 test al,al + JNE
  4. 将 JNE 替换为 JMP + NOP

用法（方式一：指定路径 / 方式二：脚本放入安装目录）:
  python patch_universal.py D:\\BinaryNinja            # 部署（指定安装目录）
  python patch_universal.py D:\\BinaryNinja\\binaryninja.exe  # 部署（指定 exe）
  python patch_universal.py D:\\BinaryNinja --restore  # 恢复

  cd D:\\BinaryNinja
  python patch_universal.py                            # 部署（自动探测）
  python patch_universal.py --restore                  # 恢复

  python patch_universal.py --dry-run                  # 仅分析，不写入
  兼容旧参数: --exe path/to/binaryninja.exe
"""

import struct, shutil, os, sys, argparse


# ── PE 解析 ──────────────────────────────────────────────────────────────────

class PEInfo:
    def __init__(self, path):
        with open(path, 'rb') as f:
            self.data = f.read()

        if self.data[:2] != b'MZ':
            raise ValueError('不是有效的 PE 文件')

        pe_off = struct.unpack_from('<I', self.data, 0x3C)[0]
        if self.data[pe_off:pe_off+4] != b'PE\x00\x00':
            raise ValueError('PE 签名无效')

        coff_off = pe_off + 4
        num_sections = struct.unpack_from('<H', self.data, coff_off + 2)[0]
        opt_hdr_size = struct.unpack_from('<H', self.data, coff_off + 16)[0]
        opt_off = coff_off + 20
        magic = struct.unpack_from('<H', self.data, opt_off)[0]

        if magic == 0x20B:
            self.image_base = struct.unpack_from('<Q', self.data, opt_off + 24)[0]
        elif magic == 0x10B:
            self.image_base = struct.unpack_from('<I', self.data, opt_off + 28)[0]
        else:
            raise ValueError(f'未知 magic: 0x{magic:X}')

        self.sections = []
        sec_off = opt_off + opt_hdr_size
        for _ in range(num_sections):
            name = self.data[sec_off:sec_off+8].rstrip(b'\x00').decode('ascii', errors='replace')
            vsize   = struct.unpack_from('<I', self.data, sec_off + 8)[0]
            vaddr   = struct.unpack_from('<I', self.data, sec_off + 12)[0]
            raw_sz  = struct.unpack_from('<I', self.data, sec_off + 16)[0]
            raw_ptr = struct.unpack_from('<I', self.data, sec_off + 20)[0]
            chars   = struct.unpack_from('<I', self.data, sec_off + 36)[0]
            self.sections.append({
                'name': name, 'vaddr': vaddr, 'vsize': vsize,
                'raw_ptr': raw_ptr, 'raw_sz': raw_sz, 'chars': chars,
            })
            sec_off += 40

    def rva_to_offset(self, rva):
        for s in self.sections:
            if s['vaddr'] <= rva < s['vaddr'] + s['raw_sz']:
                return rva - s['vaddr'] + s['raw_ptr']
        raise ValueError(f'RVA 0x{rva:X} 不在任何节内')

    def offset_to_rva(self, file_off):
        for s in self.sections:
            if s['raw_ptr'] <= file_off < s['raw_ptr'] + s['raw_sz']:
                return file_off - s['raw_ptr'] + s['vaddr']
        raise ValueError(f'文件偏移 0x{file_off:X} 不在任何节内')

    def get_section(self, file_off=None, rva=None):
        for s in self.sections:
            if file_off is not None and s['raw_ptr'] <= file_off < s['raw_ptr'] + s['raw_sz']:
                return s
            if rva is not None and s['vaddr'] <= rva < s['vaddr'] + s['raw_sz']:
                return s
        return None


# ── 字符串搜索 ───────────────────────────────────────────────────────────────

def find_string_offsets(pe, needle):
    """在数据节中搜索 ASCII 字符串，返回文件偏移列表。"""
    needle_bytes = needle.encode('ascii')
    results = []
    for s in pe.sections:
        if s['chars'] & 0x20000000:  # 跳过代码节
            continue
        start = s['raw_ptr']
        end = start + s['raw_sz']
        pos = start
        while True:
            pos = pe.data.find(needle_bytes, pos, end)
            if pos == -1:
                break
            results.append(pos)
            pos += 1
    return results


def find_lea_refs_to_va(pe, target_va, search_section='.text'):
    """在指定代码节中搜索引用 target_va 的 LEA r64, [rip+disp32] 指令。"""
    results = []
    for s in pe.sections:
        if s['name'] != search_section:
            continue
        start = s['raw_ptr']
        end = start + s['raw_sz'] - 7

        for off in range(start, end):
            b0 = pe.data[off]
            b1 = pe.data[off + 1]
            # LEA r64, [rip+disp32]: 48/4C 8D [modrm] [disp32]
            if b0 in (0x48, 0x4C) and b1 == 0x8D:
                modrm = pe.data[off + 2]
                if (modrm & 0xC7) == 0x05:  # RIP-relative
                    disp = struct.unpack_from('<i', pe.data, off + 3)[0]
                    next_ip_file = off + 7
                    next_ip_rva = next_ip_file - s['raw_ptr'] + s['vaddr']
                    computed_va = pe.image_base + next_ip_rva + disp
                    if computed_va == target_va:
                        results.append(off)
    return results


# ── JNE 定位 ─────────────────────────────────────────────────────────────────

def find_test_jne_before(pe, anchor_off, max_back=128):
    """从 anchor_off 向前搜索 84 C0 0F 85 (test al,al; JNE)。

    返回 (jne_off, jne_disp, dist)；若 JNE 已被补丁为 E9..90 则返回
    ('patched', None, None)。
    """
    patched_off = None
    for i in range(max_back):
        off = anchor_off - i
        if off < 0 or off + 8 > len(pe.data):
            break
        if pe.data[off] == 0x84 and pe.data[off + 1] == 0xC0:
            if patched_off is None:
                # test al,al 后紧跟 E9 xx xx xx xx 90 → 已补丁（JMP+NOP）
                if (pe.data[off + 2] == 0xE9
                        and off + 7 < len(pe.data)
                        and pe.data[off + 7] == 0x90):
                    patched_off = off
            if pe.data[off + 2] == 0x0F and pe.data[off + 3] == 0x85:
                jne_off = off + 2
                jne_disp = struct.unpack_from('<i', pe.data, off + 4)[0]
                return jne_off, jne_disp, anchor_off - off
    if patched_off is not None:
        return 'patched', None, None
    return None, None, None


# ── 补丁逻辑 ─────────────────────────────────────────────────────────────────

def apply_patch(data, jne_off, jne_disp):
    """将 JNE rel32 替换为 JMP rel32 + NOP。"""
    new_disp = jne_disp + 1  # JMP 比 JNE 少 1 字节操作码，偏移 +1 跳过 NOP
    patched = struct.pack('<Bi', 0xE9, new_disp) + b'\x90'
    result = bytearray(data)
    result[jne_off:jne_off + 6] = patched
    return bytes(result)


# ── 主流程 ───────────────────────────────────────────────────────────────────

# 锚点字符串列表 (按可靠性排序)
ANCHOR_STRINGS = [
    'The provided license is invalid',
    'This version of Binary Ninja requires',
    'License Required',
    'Locate license file',
    'Failed while storing license file',
    'Failed to overwrite outdated license',
]

def main():
    ap = argparse.ArgumentParser(description='Binary Ninja EXE 通用许可证绕过补丁')
    ap.add_argument('target', nargs='?', default=None,
                    help='Binary Ninja 安装目录或 binaryninja.exe 路径（省略时自动查找）')
    ap.add_argument('--exe', default=None, help='binaryninja.exe 路径（兼容旧参数）')
    ap.add_argument('--restore', action='store_true', help='从备份恢复')
    ap.add_argument('--dry-run', action='store_true', help='仅分析，不写入')
    args = ap.parse_args()

    # ── 解析目标：位置参数 > --exe > 自动探测 ──
    exe_path = args.target or args.exe
    if exe_path:
        if os.path.isdir(exe_path):
            exe_path = os.path.join(exe_path, 'binaryninja.exe')
    else:
        # 放入安装目录直接运行：探测当前目录 / 脚本目录 / 父目录
        candidates = []
        here = os.path.dirname(os.path.abspath(__file__))
        for base in (os.getcwd(), here, os.path.dirname(here)):
            p = os.path.join(base, 'binaryninja.exe')
            if os.path.exists(p):
                candidates.append(p)
        if len(set(candidates)) > 1:
            print(f'[ERROR] 找到多个 binaryninja.exe，请指定路径')
            for c in sorted(set(candidates)):
                print(f'  {c}')
            return 1
        exe_path = candidates[0] if candidates else None

    if not exe_path or not os.path.exists(exe_path):
        print(f'[ERROR] 未找到 binaryninja.exe（可传入安装目录或 exe 路径）')
        return 1

    print('=' * 55)
    print('  Binary Ninja EXE 通用许可证绕过补丁')
    print('=' * 55)
    print(f'\n[*] 文件: {exe_path}')

    if args.restore:
        bak = exe_path + '.bak'
        if os.path.exists(bak):
            shutil.copy2(bak, exe_path)
            print(f'[OK] 已恢复: {exe_path}')
        else:
            print(f'[ERROR] 备份不存在: {bak}')
        return 0

    # ── 步骤 1: 解析 PE ──
    print('\n[1/5] 解析 PE 结构...')
    try:
        pe = PEInfo(exe_path)
    except Exception as e:
        print(f'[ERROR] PE 解析失败: {e}')
        return 1
    print(f'  ImageBase: 0x{pe.image_base:X}')
    print(f'  节表: {", ".join(s["name"] for s in pe.sections)}')

    # ── 步骤 2: 搜索锚点字符串 ──
    print('\n[2/5] 搜索锚点字符串...')

    best = None
    for term in ANCHOR_STRINGS:
        offsets = find_string_offsets(pe, term)
        if not offsets:
            continue
        str_off = offsets[0]
        str_rva = pe.offset_to_rva(str_off)
        str_va = pe.image_base + str_rva

        # 找引用该字符串的 LEA 指令
        lea_offs = find_lea_refs_to_va(pe, str_va)
        if not lea_offs:
            continue

        for lea_off in lea_offs:
            # 从 LEA 向前搜索 test al,al + JNE
            jne_off, jne_disp, dist = find_test_jne_before(pe, lea_off)
            if jne_off == 'patched':
                best = {
                    'term': term,
                    'str_off': str_off,
                    'lea_off': lea_off,
                    'jne_off': None,
                    'jne_disp': None,
                    'lea_to_jne': dist,
                    'patched': True,
                }
                break
            if jne_off is not None and jne_disp > 0x100:
                best = {
                    'term': term,
                    'str_off': str_off,
                    'lea_off': lea_off,
                    'jne_off': jne_off,
                    'jne_disp': jne_disp,
                    'lea_to_jne': dist,
                    'patched': False,
                }
                break
        if best:
            break

    if not best:
        print('[ERROR] 未找到可定位的许可证检查 JNE')
        print('  尝试过的锚点: ' + ', '.join(f'"{t}"' for t in ANCHOR_STRINGS))
        print('  此版本可能不兼容通用补丁方案')
        return 1

    if best.get('patched'):
        print(f'  锚点字符串: "{best["term"]}"')
        print(f'  [SKIP] 已经补丁过（JNE 已变为 JMP+NOP）')
        return 0

    jne_rva = pe.offset_to_rva(best['jne_off'])
    print(f'  锚点字符串: "{best["term"]}"')
    print(f'  字符串文件偏移: 0x{best["str_off"]:X}')
    print(f'  LEA 引用: 文件偏移 0x{best["lea_off"]:X}')
    print(f'  JNE 位置: 文件偏移 0x{best["jne_off"]:X}  RVA 0x{jne_rva:X}')
    print(f'  LEA 到 JNE 距离: {best["lea_to_jne"]} 字节')
    print(f'  JNE 偏移: +0x{best["jne_disp"]:X}')

    # ── 步骤 3: 验证原始字节 ──
    print('\n[3/5] 验证原始字节...')
    orig_bytes = pe.data[best['jne_off']:best['jne_off']+6]
    expected_jne = bytes([0x0F, 0x85]) + struct.pack('<i', best['jne_disp'])
    if orig_bytes == expected_jne:
        print(f'  [OK] 原始字节: {orig_bytes.hex(" ")} (JNE +0x{best["jne_disp"]:X})')
    elif orig_bytes[0] == 0xE9 and orig_bytes[5] == 0x90:
        print(f'  [SKIP] 已经补丁过: {orig_bytes.hex(" ")}')
        return 0
    else:
        print(f'  [ERROR] 字节不匹配: {orig_bytes.hex(" ")}')
        return 1

    # ── 步骤 4: 计算补丁 ──
    print('\n[4/5] 计算补丁...')
    patched_jne_disp = best['jne_disp'] + 1
    patched_bytes = struct.pack('<Bi', 0xE9, patched_jne_disp) + b'\x90'
    print(f'  原始: {orig_bytes.hex(" ")}  (JNE +0x{best["jne_disp"]:X})')
    print(f'  补丁: {patched_bytes.hex(" ")}  (JMP +0x{patched_jne_disp:X}, NOP)')

    if args.dry_run:
        print(f'\n  [DRY-RUN] 不实际写入')
        return 0

    # ── 步骤 5: 写入补丁 ──
    print('\n[5/5] 写入补丁...')

    # 备份
    bak_path = exe_path + '.bak'
    if not os.path.exists(bak_path):
        shutil.copy2(exe_path, bak_path)
        print(f'  备份: {bak_path}')

    patched_data = apply_patch(pe.data, best['jne_off'], best['jne_disp'])
    with open(exe_path, 'wb') as f:
        f.write(patched_data)

    # 验证
    verify = open(exe_path, 'rb').read()
    verify_bytes = verify[best['jne_off']:best['jne_off']+6]
    if verify_bytes == patched_bytes:
        print(f'  [OK] 验证通过: {verify_bytes.hex(" ")}')
    else:
        print(f'  [ERROR] 写入验证失败: {verify_bytes.hex(" ")}')
        return 1

    print('\n' + '=' * 55)
    print('  补丁成功!')
    print('=' * 55)
    print(f'\n  锚点: "{best["term"]}"')
    print(f'  补丁 RVA: 0x{jne_rva:X}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
