"""Binary Ninja headless license hook。

在 import binaryninja 之后、使用任何 BN API 之前调用 apply_license_hook()，
将 BNIsLicenseValidated 的入口内存补丁为 `mov eax, 1; ret`（恒真），
绕过 headless/API 模式下的 license 验证（与 version.dll 劫持同原理，
仅修改内存，不改动 DLL 文件）。

用法（MCP 启动时）:
    from bn_license_hook import apply_license_hook
    apply_license_hook()
"""

import ctypes
from ctypes import wintypes

#: BNIsLicenseValidated 在 binaryninjacore.dll 中的 RVA（v5.3.9434）
BN_IS_LICENSE_VALIDATED_RVA = 0x14A59B0

#: mov eax, 1; ret（6 字节）
PATCH_BYTES = b"\xB8\x01\x00\x00\x00\xC3"

PAGE_EXECUTE_READWRITE = 0x40


def apply_license_hook() -> bool:
    """将 BNIsLicenseValidated 入口 patch 为恒真。成功返回 True。"""
    try:
        dll = ctypes.WinDLL("binaryninjacore.dll")
    except OSError:
        # 可能未加载，尝试从 BN 安装目录加载
        import os

        for cand in (r"D:\BinaryNinja\binaryninjacore.dll",):
            if os.path.exists(cand):
                dll = ctypes.WinDLL(cand)
                break
        else:
            raise RuntimeError("binaryninjacore.dll 未加载且未找到")

    base = ctypes.cast(dll._handle, ctypes.c_void_p).value
    target = base + BN_IS_LICENSE_VALIDATED_RVA

    k32 = ctypes.windll.kernel32
    old = wintypes.DWORD()
    if not k32.VirtualProtect(ctypes.c_void_p(target), len(PATCH_BYTES), PAGE_EXECUTE_READWRITE, ctypes.byref(old)):
        raise ctypes.WinError()

    # 写入补丁
    ctypes.memmove(ctypes.c_void_p(target), PATCH_BYTES, len(PATCH_BYTES))
    k32.VirtualProtect(ctypes.c_void_p(target), len(PATCH_BYTES), old, ctypes.byref(old))

    # 验证
    func_type = ctypes.CFUNCTYPE(ctypes.c_bool)
    fn = func_type(target)
    return bool(fn())


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
