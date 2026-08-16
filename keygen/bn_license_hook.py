"""Binary Ninja headless license hook。

在 import binaryninja 之后、使用任何 BN API 之前调用 apply_license_hook()，
绕过 headless/API 模式下的 license 验证（与 version.dll 劫持同原理，
仅修改内存，不改动 DLL 文件）。

原理（v5.3.9434 逆向）：
  license_init (0x1814A3790) 中有 6 处条件跳转，在 license 无效时跳到
  throw 消息构造区（0x14A5340-0x14A5420）抛出 C++ 异常
  ("License is not valid")。将这 6 处跳转全部 NOP，使失败分支自然落入
  成功路径（设置验证标志），BN 即认为 license 有效。
  同时将 BNIsLicenseValidated 入口 patch 为 `mov eax,1; ret`（恒真）。

用法（MCP 启动时）:
    from bn_license_hook import apply_license_hook
    apply_license_hook()
"""

import ctypes
from ctypes import wintypes

#: BNIsLicenseValidated 在 binaryninjacore.dll 中的 RVA（v5.3.9434）
BN_IS_LICENSE_VALIDATED_RVA = 0x14A59B0

#: license_init 中 6 处"失败跳转 throw"的 RVA（NOP 后落入成功路径）
THROW_JUMPS_RVA = [
    0x14A37F1,  # jne 0x14A5340 (入口检查)
    0x14A3B50,  # je  0x14A5348 (JSON 解析检查)
    0x14A3D50,  # jne 0x14A5371 (280 长度检查)
    0x14A446C,  # je  0x14A539A (验签结果检查)
    0x14A494B,  # je  0x14A53C3 (后续检查)
    0x14A4B17,  # je  0x14A53EB (后续检查)
]

#: mov eax, 1; ret（6 字节）
PATCH_BYTES = b"\xB8\x01\x00\x00\x00\xC3"

PAGE_EXECUTE_READWRITE = 0x40

#: 内置 license 文本（任意格式即可，验证已被绕过；需提供以让 license_init 走完流程）
FALLBACK_LICENSE = (
    '[{"product":"Binary Ninja Personal","email":"hook@local",'
    '"serial":"0000000000000000","created":"2026-01-01T00:00:00.000+00:00",'
    '"type":"User","count":1,"data":"","expiresEpoch":0,"signature":""}]'
)


def apply_license_hook() -> bool:
    """绕过 BN headless license 验证。成功返回 True。

    注意：必须提供 license 文本（BNSetLicense），否则 license_init
    流程因空对象崩溃。未设置时使用内置 FALLBACK_LICENSE。
    """
    try:
        dll = ctypes.WinDLL("binaryninjacore.dll")
    except OSError:
        import os

        for cand in (r"D:\BinaryNinja\binaryninjacore.dll",):
            if os.path.exists(cand):
                dll = ctypes.WinDLL(cand)
                break
        else:
            raise RuntimeError("binaryninjacore.dll 未加载且未找到")

    base = ctypes.cast(dll._handle, ctypes.c_void_p).value
    k32 = ctypes.windll.kernel32

    # 0. 提供 license 文本（BNSetLicense 是流程必需；重复调用无害）
    dll.BNSetLicense.argtypes = [ctypes.c_char_p]
    dll.BNSetLicense(FALLBACK_LICENSE.encode())

    # 1. 6 处 throw 跳转 NOP
    for rva in THROW_JUMPS_RVA:
        addr = base + rva
        old = wintypes.DWORD()
        if not k32.VirtualProtect(
            ctypes.c_void_p(addr), 6, PAGE_EXECUTE_READWRITE, ctypes.byref(old)
        ):
            raise ctypes.WinError()
        ctypes.memmove(ctypes.c_void_p(addr), b"\x90" * 6, 6)
        k32.VirtualProtect(ctypes.c_void_p(addr), 6, old, ctypes.byref(old))

    # 2. BNIsLicenseValidated -> mov eax,1; ret
    addr = base + BN_IS_LICENSE_VALIDATED_RVA
    old = wintypes.DWORD()
    if not k32.VirtualProtect(
        ctypes.c_void_p(addr), len(PATCH_BYTES), PAGE_EXECUTE_READWRITE, ctypes.byref(old)
    ):
        raise ctypes.WinError()
    ctypes.memmove(ctypes.c_void_p(addr), PATCH_BYTES, len(PATCH_BYTES))
    k32.VirtualProtect(ctypes.c_void_p(addr), len(PATCH_BYTES), old, ctypes.byref(old))

    # 验证
    func_type = ctypes.CFUNCTYPE(ctypes.c_bool)
    fn = func_type(base + BN_IS_LICENSE_VALIDATED_RVA)
    return bool(fn())


def is_license_set(dll) -> bool:
    """检查是否已设置 license（全局槽非空）。"""
    base = ctypes.cast(dll._handle, ctypes.c_void_p).value
    slot = ctypes.c_void_p(base + 0xAA4A020)
    return ctypes.c_ulonglong.from_address(ctypes.addressof(slot)).value != 0


def is_hook_active() -> bool:
    """检查 BNIsLicenseValidated 是否已被 patch（恒真）。"""
    try:
        dll = ctypes.WinDLL("binaryninjacore.dll")
    except OSError:
        return False
    base = ctypes.cast(dll._handle, ctypes.c_void_p).value
    func_type = ctypes.CFUNCTYPE(ctypes.c_bool)
    fn = func_type(base + BN_IS_LICENSE_VALIDATED_RVA)
    return bool(fn())


if __name__ == "__main__":
    print("hook 前 BNIsLicenseValidated =", is_hook_active())
    print("apply =", apply_license_hook())
    print("hook 后 BNIsLicenseValidated =", is_hook_active())
