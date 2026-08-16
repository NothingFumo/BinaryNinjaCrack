# frida_attach_license.py: attach 已加载 BN 的进程, 观察 license 全局状态
import sys
import time

import frida

JS = r"""
'use strict';
var base = Module.getBaseAddress('binaryninjacore.dll');
console.log('[+] base = ' + base);

// 读验证标志 (RVA 0xAA4A088)
var flag = base.add(0xAA4A088);
console.log('[+] 验证标志 @ ' + flag + ' = ' + flag.readU8());

// 读 product 指针相关
var pfn = base.add(0x14A5A00);
console.log('[+] BNSetLicense @ ' + pfn);

// 观察 BNGetProduct: RVA 0x14A5900 返回 c_char_p
var getProd = base.add(0x14A5900);
console.log('[+] BNGetProduct @ ' + getProd);

// 手动调用 BNGetProduct 看当前值
var f = new NativeFunction(getProd, 'pointer', []);
var p = f();
console.log('[+] BNGetProduct() = ' + p.readCString());

// 验证标志是否被写过: 找它旁边是否有验证通过痕迹
console.log('[+] flag+1 = ' + base.add(0xAA4A089).readU8());
"""


def main():
    pid = int(sys.argv[1])
    session = frida.attach(pid)
    script = session.create_script(JS)
    script.on("message", lambda msg, data: print(msg.get("payload") or msg))
    script.load()
    time.sleep(3)
    session.detach()


if __name__ == "__main__":
    main()
