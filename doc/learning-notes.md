# 破解补丁学习笔记

个人学习逆向工程中关于软件许可证绕过的笔记，记录方法论和踩坑经验。

---

## 1. 许可证绕过的通用方法论

### 1.1 核心思路

所有许可证绕过的本质都是：**让程序认为许可证有效**。

实现路径只有两条：
1. **提供有效许可证**（注册机、密钥替换）
2. **跳过检查逻辑**（patch 条件跳转、patch 验证函数）

### 1.2 攻击面选择

```
                    ┌─ EXE 入口点 patch（最直接）
                    │
攻击面 ────────────├─ DLL 劫持（不改原始文件）
                    │
                    ├─ 内存 patch（运行时修改）
                    │
                    └─ 密钥替换（伪造有效凭证）
```

选择标准：
- **是否修改原始文件**：DLL 劫持 > EXE patch
- **是否跨版本**：函数 patch > 偏移 patch
- **复杂度**：少导出 DLL > 多导出 DLL

---

## 2. DLL 劫持技术

### 2.1 原理

Windows DLL 搜索顺序（简化）：
1. **应用程序所在目录**（最高优先级）
2. System32
3. PATH 环境变量

在应用目录放置同名 DLL 即可劫持加载。

### 2.2 选择可劫持 DLL 的标准

```python
import pefile
pe = pefile.PE('target.dll')
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll_name = entry.dll.decode()
    # 检查是否在 KnownDLLs 注册表中
    # 导出数越少越好
```

优先选择：
- **不在 KnownDLLs 列表中**
- **导出函数少**（减少转发桩工作量）
- **被核心模块导入**（确保在目标代码执行前加载）

### 2.3 代理 DLL 实现模板

```c
// 1. 声明函数指针数组
static FARPROC fp[N] = {0};

// 2. DllMain 中加载真实 DLL 并解析
static void InitReal(void) {
    char path[MAX_PATH];
    GetSystemDirectoryA(path, MAX_PATH);
    strcat(path, "\\target.dll");
    hReal = LoadLibraryA(path);
    fp[0] = GetProcAddress(hReal, "Export1");
    // ...
}

// 3. Patch 目标函数
static void PatchTarget(void) {
    HMODULE hCore = GetModuleHandleA("core.dll");
    FARPROC pFunc = GetProcAddress(hCore, "TargetFunc");
    BYTE *addr = (BYTE*)pFunc;
    DWORD old;
    VirtualProtect(addr, 8, PAGE_EXECUTE_READWRITE, &old);
    addr[0] = 0xB8;  // mov eax, 1
    addr[1] = 0x01;
    addr[5] = 0xC3;  // ret
    VirtualProtect(addr, 8, old, &old);
    FlushInstructionCache(GetCurrentProcess(), addr, 8);
}

// 4. 转发函数
BOOL __stdcall Export1(...) {
    typedef BOOL(__stdcall *f)(...);
    return fp[0] ? ((f)fp[0])(...) : FALSE;
}
```

### 2.4 踩坑记录

**问题 1：CRT 的 DllMain 包装器导致 loader 死锁**

使用 `-nostdlib` 编译时，CRT 的初始化代码被跳过，但某些 DLL 内部依赖 CRT。解决：不使用 `-nostdlib`，而是手动控制入口点。

**问题 2：汇编桩在某些环境下崩溃**

MASM 风格的 `jmp qword ptr [real_xxx]` 在某些 Windows 版本下行为不一致。解决：改用 C 函数指针转发，牺牲一点性能换取稳定性。

**问题 3：DLL 无法正常加载**

忘记在 .def 文件中导出所有函数，或导出名拼写错误。解决：用 `dumpbin /exports` 对比真实 DLL 的导出表。

---

## 3. EXE 补丁技术

### 3.1 固定偏移 vs 字符串锚点

| 方法 | 优点 | 缺点 |
|------|------|------|
| 固定偏移 | 简单直接 | 版本更新即失效 |
| 字符串锚点 | 跨版本兼容 | 实现复杂，依赖字符串稳定性 |

### 3.2 字符串锚点定位算法

```
1. 在数据节搜索许可证错误字符串
2. 计算字符串 RVA → VA
3. 在代码节搜索 LEA r64, [rip+disp32] 引用
   - 操作码: 48/4C 8D [modrm] [disp32]
   - modrm & 0xC7 == 0x05 表示 RIP-relative
   - 验证: (指令地址 + 7) + disp32 == 目标 VA
4. 从 LEA 向前搜索 test al,al + JNE
   - 84 C0 0F 85 xx xx xx xx
5. 补丁 JNE → JMP + NOP
```

### 3.3 x86 条件跳转补丁对照表

| 原始指令 | 操作码 | 补丁指令 | 操作码 | 说明 |
|----------|--------|----------|--------|------|
| JNE rel32 | 0F 85 | JMP rel32 | E9 | 偏移 +1 补偿 |
| JE rel32 | 0F 84 | JMP rel32 | E9 | 偏移 +1 补偿 |
| JNE rel32 | 0F 85 | NOP ×6 | 90 ×6 | 删除跳转 |
| JNE rel8 | 75 | NOP ×2 | 90 ×2 | 短跳转版本 |

**注意**：JMP (E9) 是 5 字节，JNE (0F 85) 是 6 字节，需要多 NOP 1 字节或调整偏移。

---

## 4. 内存 Patch 技术

### 4.1 标准三步

```c
// 1. 修改内存保护
DWORD old;
VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &old);

// 2. 写入补丁
memcpy(addr, patch_bytes, size);

// 3. 恢复保护 + 刷新指令缓存
VirtualProtect(addr, size, old, &old);
FlushInstructionCache(GetCurrentProcess(), addr, size);
```

### 4.2 常见 patch 模式

```c
// 强制函数返回 TRUE
// mov eax, 1; ret
BYTE patch[] = {0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3};

// 强制函数返回 FALSE
// xor eax, eax; ret
BYTE patch[] = {0x31, 0xC0, 0xC3};

// NOP 滑板（跳过指令）
BYTE patch[] = {0x90, 0x90, 0x90, 0x90};
```

---

## 5. PE 文件结构要点

### 5.1 关键偏移

```
0x00: MZ 签名
0x3C: PE 头偏移
PE+4: COFF 头
COFF+20: Optional 头
Optional+24 (PE32+) / +28 (PE32): ImageBase
```

### 5.2 RVA 到文件偏移转换

```python
def rva_to_offset(sections, rva):
    for s in sections:
        if s['vaddr'] <= rva < s['vaddr'] + s['raw_sz']:
            return rva - s['vaddr'] + s['raw_ptr']
    raise ValueError(f'RVA 0x{rva:X} 不在任何节内')
```

### 5.3 导出表解析

```python
import pefile
pe = pefile.PE('target.dll')
for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    name = exp.name.decode() if exp.name else f'ordinal_{exp.ordinal}'
    rva = exp.address
    print(f'{name}  RVA=0x{rva:X}')
```

---

## 6. 工具链

| 工具 | 用途 |
|------|------|
| **x64dbg** | 动态调试，验证补丁效果 |
| **Binary Ninja / IDA** | 静态分析，理解程序逻辑 |
| **pefile** (Python) | PE 文件解析，自动化脚本 |
| **MinGW-w64** | 编译代理 DLL |
| **pycryptodome** | RSA 密钥生成 |

---

## 7. 经验总结

1. **先分析再动手**：理解验证流程比盲目 patch 更重要
2. **最小修改原则**：能改 1 字节就不改 2 字节
3. **保留备份**：补丁前一定要备份原始文件
4. **验证效果**：用 x64dbg 确认 patch 是否生效
5. **考虑恢复**：方案应该易于恢复（DLL 劫持 > EXE patch）
6. **跨版本思考**：字符串锚点 > 固定偏移
7. **最小攻击面**：选择最简单的攻击路径（17 导出 > 180 导出）
