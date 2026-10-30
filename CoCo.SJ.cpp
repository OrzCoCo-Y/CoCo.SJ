#include <stdio.h>
#include <iostream>
#include <Windows.h>
#include <string>
#include <tlhelp32.h>
#include <fstream>
#include <iomanip>
#include <locale>
#include <codecvt>
using namespace std;

HANDLE 游戏句柄 = nullptr;
DWORD pid = 0;
HWND 游戏窗口句柄 = nullptr;

uintptr_t BaseAddr = 0;
uintptr_t GName = 0;
uintptr_t GObject = 0;

const char* OUTPUT_FILE = "FadeoutSDK/Object.cpp";

// 获取进程ID
DWORD GetProcessIdByName(const wchar_t* exeName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exeName) == 0) {
                CloseHandle(hSnapshot);
                return pe.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return 0;
}

// 获取模块基址
uintptr_t GetModuleBaseAddress(DWORD pid, const wchar_t* moduleName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32 me = { sizeof(me) };
    if (Module32First(hSnapshot, &me)) {
        do {
            if (_wcsicmp(me.szModule, moduleName) == 0) {
                CloseHandle(hSnapshot);
                return (uintptr_t)me.modBaseAddr;
            }
        } while (Module32Next(hSnapshot, &me));
    }
    CloseHandle(hSnapshot);
    return 0;
}

bool 初始化()
{
    const wchar_t* exeName = L"Grapple-Win64-Shipping.exe";

    游戏窗口句柄 = FindWindowW(L"UnrealWindow", nullptr);
    if (!游戏窗口句柄) {
        printf("[-] 找不到游戏窗口!\n");
        return false;
    }

    GetWindowThreadProcessId(游戏窗口句柄, &pid);
    游戏句柄 = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!游戏句柄) {
        printf("[-] 无法打开进程! 错误码: %d\n", GetLastError());
        return false;
    }

    BaseAddr = GetModuleBaseAddress(pid, exeName);
    if (!BaseAddr) {
        printf("[-] 无法获取模块基址!\n");
        return false;
    }

    // 注意：这些偏移需要根据实际版本验证！
    GName = BaseAddr + 0x36D52C0+0x10;   
    GObject = BaseAddr + 0x36EC978+0x10; 

    printf("[+] 成功附加到进程 PID: %d\n", pid);
    printf("[+] 模块基址: 0x%llX\n", BaseAddr);
    printf("[+] GName 地址: 0x%llX\n", GName);
    printf("[+] GObject 地址: 0x%llX\n", GObject);
    return true;
}

// 安全内存读取
bool Read(uintptr_t addr, void* buf, size_t size)
{
    SIZE_T bytesRead;
    return ReadProcessMemory(游戏句柄, (LPCVOID)addr, buf, size, &bytesRead) && bytesRead == size;
}

template<typename T>
T Read(uintptr_t addr)
{
    T value;
    if (!Read(addr, &value, sizeof(T)))
        memset(&value, 0, sizeof(T));
    return value;
}

struct FNameEntryHeader
{
    uint16_t bIsWide : 1;
    uint16_t LowercaseProbeHash : 5;
    uint16_t Len : 10;
};

struct FNameEntry
{
    FNameEntryHeader Header;
    union
    {
        char    AnsiName[1024];
        wchar_t WideName[1024];
    };
};

string GetName(int NameId)
{
    if (NameId == 0) return "None";

    uintptr_t BlockIndex = NameId >> 16;
    uintptr_t BlockOffset = NameId & 0xFFFF;

    uintptr_t BlockPtrAddr = GName + BlockIndex * 8;
    uint64_t BlockPtr = Read<uint64_t>(BlockPtrAddr);
    if (!BlockPtr) return "nullptr";

    uintptr_t NameEntryAddr = BlockPtr + BlockOffset * 0x2; // 每个 FNameEntryHeader 占 2 字节？实际是完整结构
    // 更准确：FNameEntry 是变长结构，但通常按块排列，这里简化处理为直接偏移
    // 实际引擎中可能需要更复杂的解析，此处假设可直接访问
    FNameEntry info = Read<FNameEntry>(NameEntryAddr);
    string name;

    if (info.Header.bIsWide) {
        wstring wstr(info.WideName, info.Header.Len);
        // 转 UTF-8
        wstring_convert<codecvt_utf8_utf16<wchar_t>> conv;
        name = conv.to_bytes(wstr);
    }
    else {
        name = string(info.AnsiName, info.Header.Len);
    }

    // 移除路径前缀，只保留最后一部分
    auto pos = name.rfind('/');
    if (pos != string::npos) {
        name = name.substr(pos + 1);
    }

    return name;
}

// ✅ 修复：正确计算对象地址
uint64_t GetAllObject(size_t id)
{
    constexpr size_t NUM_PER_CHUNK = 65536;
    size_t chunkIdx = id / NUM_PER_CHUNK;
    size_t inChunkIdx = id % NUM_PER_CHUNK;

    uint64_t chunks = Read<uint64_t>(GObject); // ObjObjects -> chunk 数组
    if (!chunks) return 0;

    uint64_t chunkPtr = Read<uint64_t>(chunks + 8 * chunkIdx);
    if (!chunkPtr) return 0;

    uint64_t objectEntry = chunkPtr + inChunkIdx * 0x18; // 每个 UObjectItem 占 0x18 字节
    return Read<uint64_t>(objectEntry);
}

string GetNameForObject(uint64_t Object)
{
    if (!Object) return "";
    uint32_t NameID = Read<uint32_t>(Object + 0x18);
    return GetName(NameID);
}

uint64_t GetClass(uint64_t Object)
{
    return Object ? Read<uint64_t>(Object + 0x10) : 0;
}

uint64_t GetSuperClass(uint64_t Object)
{
    return Object ? Read<uint64_t>(Object + 0x40) : 0;
}

uint64_t GetOuter(uint64_t Object)
{
    return Object ? Read<uint64_t>(Object + 0x20) : 0;
}

string dumpObject(uint64_t Object)
{
    if (!Object) return "";

    string name = GetNameForObject(Object);
    if (name.empty() || name == "None") return "";

    // 拼接 Outer 路径，限制深度防止死循环
    int depth = 0;
    for (uint64_t Outer = GetOuter(Object); Outer && depth < 10; Outer = GetOuter(Outer), ++depth)
    {
        string outerName = GetNameForObject(Outer);
        if (!outerName.empty() && outerName != "None") {
            name = outerName + "." + name;
        }
    }

    uint64_t Class = GetClass(Object);
    string classname = GetNameForObject(Class);
    if (classname.empty()) classname = "UnknownClass";

    return classname + " " + name;
}

void dump()
{
    uint32_t ObjectCount = Read<uint32_t>(GObject + 0x14); // ObjObjects+0x14 通常是 NumElements
    if (ObjectCount == 0 || ObjectCount > 1000000) {
        printf("[-] 对象数量异常: %d\n", ObjectCount);
        return;
    }

    CreateDirectoryA("FadeoutSDK", NULL);

    // 打开文件并设置 UTF-8 编码
    ofstream file(OUTPUT_FILE, ios::out | ios::binary);
    if (!file.is_open()) {
        printf("[-] 无法创建文件: %s\n", OUTPUT_FILE);
        return;
    }

    // 设置 UTF-8 输出
    file.imbue(locale(file.getloc(), new codecvt_utf8<char>));

    printf("[+] 开始扫描 %d 个对象...\n", ObjectCount);
    int validCount = 0;

    for (size_t i = 0; i < ObjectCount; i++)
    {
        if (i % 10000 == 0) {
            printf("[*] 已扫描 %zu / %d\n", i, ObjectCount);
        }

        uint64_t Object = GetAllObject(i);
        string desc = dumpObject(Object);
        if (!desc.empty()) {
            file << "[" << hex << uppercase << setfill('0') << setw(12) << Object << "] " << desc << endl;
            validCount++;
        }
    }
    file.close();
    printf("[+] 扫描完成! 有效对象: %d / %d\n", validCount, ObjectCount);
    printf("[+] 已保存到: %s\n", OUTPUT_FILE);
}


uint64_t GetsObject(string name)
{
    //Class CoreUObject.Class
    uint32_t ObjectCount = Read<uint32_t>(GObject + 0x14);
    for (size_t i = 0; i < ObjectCount; i++)
    {
        uint64_t Object = GetAllObject(i);
        if (dumpObject(Object) == name)
        {
            return Object;
        }
    }
    return 0;
}

bool FilterObjects(uint64_t Object)
{
    static   uint64_t obj = GetsObject("Class CoreUObject.Class");

    for (uint64_t sobj = GetClass(Object); sobj; sobj= GetSuperClass(sobj))
    {
        if (sobj == obj)
        {
            return true;
        }
    }
    return false;
}

void test()
{
    uint32_t ObjectCount = Read<uint32_t>(GObject + 0x14);
    for (size_t i = 0; i < ObjectCount; i++)
    {
        uint64_t Object = GetAllObject(i);
        if (!Object)continue;
        if (FilterObjects(Object))
        {
            printf("[%p]\n", Object);
        }
    }

}



//int main()
//{
//    if (!初始化()) {
//        system("pause");
//        return 1;
//    }
//
//    //dump();
//    test();
//
//
//    printf("按任意键退出...\n");
//    system("pause");
//    return 0;
//}