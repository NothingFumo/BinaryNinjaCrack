/*
 * version.dll 代理 - 最简 DLL 劫持方案
 * 17 个导出转发 + 直接 patch BNIsLicenseValidated 函数体
 *
 * 部署: 复制 version.dll 到应用目录即可
 * 恢复: 删除 version.dll 即可
 */

#define NULL ((void*)0)
typedef void* HMODULE;
typedef void* FARPROC;
typedef void* LPVOID;
typedef void* HINSTANCE;
typedef unsigned long DWORD;
typedef int BOOL;
typedef unsigned char BYTE;
typedef char* LPSTR;
typedef const char* LPCSTR;
typedef unsigned short WCHAR;
typedef WCHAR* LPWSTR;
typedef const WCHAR* LPCWSTR;
typedef void* LPCVOID;
typedef unsigned int UINT;
typedef unsigned int* PUINT;
typedef unsigned int* LPDWORD;
#define TRUE 1
#define FALSE 0
#define MAX_PATH 260
#define PAGE_EXECUTE_READWRITE 0x40
#define DLL_PROCESS_ATTACH 1

extern HMODULE __stdcall LoadLibraryA(LPCSTR);
extern FARPROC __stdcall GetProcAddress(HMODULE, LPCSTR);
extern HMODULE __stdcall GetModuleHandleA(LPCSTR);
extern DWORD __stdcall GetSystemDirectoryA(LPSTR, DWORD);
extern BOOL __stdcall VirtualProtect(LPVOID, DWORD, DWORD, DWORD*);
extern BOOL __stdcall FlushInstructionCache(void*, LPVOID, DWORD);
extern void* __stdcall GetCurrentProcess(void);
extern LPSTR lstrcatA(LPSTR, LPCSTR);

/* 真实 DLL 预加载 */
static HMODULE hReal = NULL;
static FARPROC fp[17] = {0};

static void InitReal(void) {
    char path[MAX_PATH];
    if (hReal) return;
    GetSystemDirectoryA(path, MAX_PATH);
    lstrcatA(path, "\version.dll");
    hReal = LoadLibraryA(path);
    if (!hReal) return;

    fp[0]  = GetProcAddress(hReal, "GetFileVersionInfoA");
    fp[1]  = GetProcAddress(hReal, "GetFileVersionInfoByHandle");
    fp[2]  = GetProcAddress(hReal, "GetFileVersionInfoExA");
    fp[3]  = GetProcAddress(hReal, "GetFileVersionInfoExW");
    fp[4]  = GetProcAddress(hReal, "GetFileVersionInfoSizeA");
    fp[5]  = GetProcAddress(hReal, "GetFileVersionInfoSizeExA");
    fp[6]  = GetProcAddress(hReal, "GetFileVersionInfoSizeExW");
    fp[7]  = GetProcAddress(hReal, "GetFileVersionInfoSizeW");
    fp[8]  = GetProcAddress(hReal, "GetFileVersionInfoW");
    fp[9]  = GetProcAddress(hReal, "VerFindFileA");
    fp[10] = GetProcAddress(hReal, "VerFindFileW");
    fp[11] = GetProcAddress(hReal, "VerInstallFileA");
    fp[12] = GetProcAddress(hReal, "VerInstallFileW");
    fp[13] = GetProcAddress(hReal, "VerLanguageNameA");
    fp[14] = GetProcAddress(hReal, "VerLanguageNameW");
    fp[15] = GetProcAddress(hReal, "VerQueryValueA");
    fp[16] = GetProcAddress(hReal, "VerQueryValueW");
}

/* patch BNIsLicenseValidated: mov eax, 1; ret */
static void PatchLicense(void) {
    HMODULE hCore;
    FARPROC pFunc;
    BYTE *addr;
    DWORD old;

    hCore = GetModuleHandleA("binaryninjacore.dll");
    if (!hCore) return;

    pFunc = GetProcAddress(hCore, "BNIsLicenseValidated");
    if (!pFunc) return;

    addr = (BYTE*)pFunc;
    VirtualProtect(addr, 8, PAGE_EXECUTE_READWRITE, &old);

    addr[0] = 0xB8;  /* mov eax, imm32 */
    addr[1] = 0x01;
    addr[2] = 0x00;
    addr[3] = 0x00;
    addr[4] = 0x00;
    addr[5] = 0xC3;  /* ret */

    VirtualProtect(addr, 8, old, &old);
    FlushInstructionCache(GetCurrentProcess(), addr, 8);
}

BOOL DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    (void)hinst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        InitReal();
        PatchLicense();
    }
    return TRUE;
}

/* 17 个转发桩 */
BOOL __stdcall GetFileVersionInfoA(LPCSTR a, DWORD b, DWORD c, LPVOID d) {
    typedef BOOL(__stdcall *f)(LPCSTR, DWORD, DWORD, LPVOID);
    return fp[0] ? ((f)fp[0])(a,b,c,d) : FALSE;
}
BOOL __stdcall GetFileVersionInfoByHandle(LPCSTR a, void* b, DWORD c, LPVOID d) {
    typedef BOOL(__stdcall *f)(LPCSTR, void*, DWORD, LPVOID);
    return fp[1] ? ((f)fp[1])(a,b,c,d) : FALSE;
}
BOOL __stdcall GetFileVersionInfoExA(DWORD a, LPCSTR b, DWORD c, DWORD d, LPVOID e) {
    typedef BOOL(__stdcall *f)(DWORD, LPCSTR, DWORD, DWORD, LPVOID);
    return fp[2] ? ((f)fp[2])(a,b,c,d,e) : FALSE;
}
BOOL __stdcall GetFileVersionInfoExW(DWORD a, LPCWSTR b, DWORD c, DWORD d, LPVOID e) {
    typedef BOOL(__stdcall *f)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID);
    return fp[3] ? ((f)fp[3])(a,b,c,d,e) : FALSE;
}
DWORD __stdcall GetFileVersionInfoSizeA(LPCSTR a, LPDWORD b) {
    typedef DWORD(__stdcall *f)(LPCSTR, LPDWORD);
    return fp[4] ? ((f)fp[4])(a,b) : 0;
}
DWORD __stdcall GetFileVersionInfoSizeExA(DWORD a, LPCSTR b, LPDWORD c) {
    typedef DWORD(__stdcall *f)(DWORD, LPCSTR, LPDWORD);
    return fp[5] ? ((f)fp[5])(a,b,c) : 0;
}
DWORD __stdcall GetFileVersionInfoSizeExW(DWORD a, LPCWSTR b, LPDWORD c) {
    typedef DWORD(__stdcall *f)(DWORD, LPCWSTR, LPDWORD);
    return fp[6] ? ((f)fp[6])(a,b,c) : 0;
}
DWORD __stdcall GetFileVersionInfoSizeW(LPCWSTR a, LPDWORD b) {
    typedef DWORD(__stdcall *f)(LPCWSTR, LPDWORD);
    return fp[7] ? ((f)fp[7])(a,b) : 0;
}
BOOL __stdcall GetFileVersionInfoW(LPCWSTR a, DWORD b, DWORD c, LPVOID d) {
    typedef BOOL(__stdcall *f)(LPCWSTR, DWORD, DWORD, LPVOID);
    return fp[8] ? ((f)fp[8])(a,b,c,d) : FALSE;
}
DWORD __stdcall VerFindFileA(DWORD a, LPCSTR b, LPCSTR c, LPCSTR d, LPSTR e, PUINT f2, LPSTR g, PUINT h) {
    typedef DWORD(__stdcall *f)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT, LPSTR, PUINT);
    return fp[9] ? ((f)fp[9])(a,b,c,d,e,f2,g,h) : 0;
}
DWORD __stdcall VerFindFileW(DWORD a, LPCWSTR b, LPCWSTR c, LPCWSTR d, LPWSTR e, PUINT f2, LPWSTR g, PUINT h) {
    typedef DWORD(__stdcall *f)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT, LPWSTR, PUINT);
    return fp[10] ? ((f)fp[10])(a,b,c,d,e,f2,g,h) : 0;
}
DWORD __stdcall VerInstallFileA(DWORD a, LPCSTR b, LPCSTR c, LPCSTR d, LPCSTR e, LPCSTR f2, LPSTR g, PUINT h) {
    typedef DWORD(__stdcall *f)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT);
    return fp[11] ? ((f)fp[11])(a,b,c,d,e,f2,g,h) : 0;
}
DWORD __stdcall VerInstallFileW(DWORD a, LPCWSTR b, LPCWSTR c, LPCWSTR d, LPCWSTR e, LPCWSTR f2, LPWSTR g, PUINT h) {
    typedef DWORD(__stdcall *f)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT);
    return fp[12] ? ((f)fp[12])(a,b,c,d,e,f2,g,h) : 0;
}
DWORD __stdcall VerLanguageNameA(DWORD a, LPSTR b, DWORD c) {
    typedef DWORD(__stdcall *f)(DWORD, LPSTR, DWORD);
    return fp[13] ? ((f)fp[13])(a,b,c) : 0;
}
DWORD __stdcall VerLanguageNameW(DWORD a, LPWSTR b, DWORD c) {
    typedef DWORD(__stdcall *f)(DWORD, LPWSTR, DWORD);
    return fp[14] ? ((f)fp[14])(a,b,c) : 0;
}
BOOL __stdcall VerQueryValueA(LPCVOID a, LPCSTR b, LPVOID* c, PUINT d) {
    typedef BOOL(__stdcall *f)(LPCVOID, LPCSTR, LPVOID*, PUINT);
    return fp[15] ? ((f)fp[15])(a,b,c,d) : FALSE;
}
BOOL __stdcall VerQueryValueW(LPCVOID a, LPCWSTR b, LPVOID* c, PUINT d) {
    typedef BOOL(__stdcall *f)(LPCVOID, LPCWSTR, LPVOID*, PUINT);
    return fp[16] ? ((f)fp[16])(a,b,c,d) : FALSE;
}
