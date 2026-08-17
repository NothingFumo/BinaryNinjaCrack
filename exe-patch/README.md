# EXE 通用补丁方案

通过许可证错误字符串作为语义锚点，自动定位补丁点，兼容 Binary Ninja 多版本。

## 原理

```
搜索许可证错误字符串 ("The provided license is invalid" 等)
        │
        ▼
找到引用该字符串的 LEA 指令 (代码段)
        │
        ▼
从 LEA 向前搜索条件跳转 (test al,al + JNE)
        │
        ▼
将 JNE (0F 85) 替换为 JMP (E9) + NOP (90)
```

### 为什么用字符串锚点

直接补丁方案使用**固定文件偏移** `0x00113C0D`，版本更新后失效。字符串锚点方案利用许可证相关的 UI 文本（如 "license recovery"）作为定位基准，这些文本跨版本稳定。

### 补丁前后对比

```
补丁前: 84 C0 0F 85 00 08 00 00  (test al,al; JNE +0x800)
补丁后: E9 01 08 00 00 90         (JMP +0x801; NOP)
```

- `0F 85` → `E9`：条件跳转改无条件跳转
- 偏移 +1：JMP 操作码比 JNE 少 1 字节，需要调整偏移
- `90` (NOP)：填充因操作码长度差异多出的 1 字节

## 使用

### 方式一：指定 Binary Ninja 路径

```bash
python patch_universal.py D:\BinaryNinja            # 部署（指定安装目录）
python patch_universal.py D:\BinaryNinja --restore  # 恢复
# 也可直接指定 exe：
python patch_universal.py D:\BinaryNinja\binaryninja.exe
```

### 方式二：将脚本放入 Binary Ninja 目录

将 `patch_universal.py` 复制到 Binary Ninja 安装目录，直接运行：

```bash
cd D:\BinaryNinja
python patch_universal.py            # 部署（自动查找当前目录）
python patch_universal.py --restore  # 恢复
```

### 类似的使用

```bash
python patch_universal.py --dry-run   # 仅分析，不写入
python patch_universal.py --exe D:\BinaryNinja\binaryninja.exe  # 兼容旧参数
```

## 锚点字符串列表

按可靠性排序：

1. `"The provided license is invalid"`
2. `"This version of Binary Ninja requires"`
3. `"License Required"`
4. `"Locate license file"`
5. `"Failed while storing license file"`
6. `"Failed to overwrite outdated license"`

脚本会依次尝试，直到找到可定位的 JNE。

## 局限性

- 修改原始 EXE 文件
- Binary Ninja 更新后需要重新补丁（但脚本会自动适应）
- 字符串被国际化/重构后可能失效
