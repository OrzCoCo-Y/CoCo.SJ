// ============================================================================
//  GNameDump.cpp —— 读取 UE4 游戏里的“名字表”(GName)
//
//  这个程序只干三件事：
//     1. 打开游戏进程
//     2. 找到游戏里的名字表 GName
//     3. 把 NameId 翻译成名字，并把所有名字列出来
//
//  ── 先给 .NET 同事打个底 ──────────────────────────────────────────────
//   * 这里读的是“另一个进程”的内存，不能像 C# 那样 new 对象、点属性。
//     只能按“地址 + 字节数”一块一块读，跟读文件差不多。
//   * C++ 没有垃圾回收，HANDLE 这种系统资源用完要自己 CloseHandle。
//   * 下面的代码没有类、没有泛型，就是从上往下执行的普通函数。
//   * 类型对照：
//         uint8_t  = byte       uint16_t = ushort
//         uint32_t = uint       uint64_t = ulong
//         std::string 就是 C# 的 string
//   * 屏幕输出故意用英文，避免控制台编码问题；注释用中文。
//  ──────────────────────────────────────────────────────────────────────
//
//  ── 名字表长什么样 ────────────────────────────────────────────────────
//  GName 是一个对象，里面有一堆“块”(Block)，每块 128KB：
//
//      GName + 0x00 : 一把锁（8 字节，不用管）
//      GName + 0x08 : 当前写到第几块（4 字节）
//      GName + 0x0C : 当前块用了多少字节（4 字节）
//      GName + 0x10 : Blocks[0] 的地址（8 字节）
//      GName + 0x18 : Blocks[1] 的地址
//      ...
//
//  每个块里，密密麻麻排着一条条名字记录。一条记录长这样：
//
//      +0x00  2 字节“头”
//               bit0     = 1 表示 UTF-16，= 0 表示普通 ASCII
//               bit6..15 = 名字有几个字符（最多 1023）
//      +0x02  名字文字（长度就是头里的字符数）
//
//  真实内存长这样（None / ByteProperty / IntProperty）：
//
//      1E 01  4E 6F 6E 65  10 03  42 79 74 65 50 72 6F 70 65 72 74 79 ...
//      └头─┘  └─ None ─┘  └头─┘  └────── ByteProperty ──────┘
//
//  注意：名字后面没有 '\0' 结尾！所以不能当普通字符串读，
//        只能按“头里的长度”读多少算多少。
//
//  ── NameId 怎么拆 ─────────────────────────────────────────────────────
//      NameId = 0x00000003
//      高 16 位 = 0   → 第 0 块
//      低 16 位 = 3   → 块内偏移 = 3 * 2 = 6 字节
//      到第 0 块的 6 字节处一看，就是 "ByteProperty"
//
//  所以 NameId 不是“第几个名字”，而是“第几块 + 块内位置”，
//  相邻两个名字的 NameId 差值也不是 1。
// ============================================================================

#include <stdio.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <Windows.h>
#include <tlhelp32.h>

// ============================================================================
//  配置：换游戏时只改这几行
// ============================================================================

// 游戏进程名（任务管理器里看到的 exe 名字）
static const wchar_t* GAME_EXE = L"DeathlyStillnessGame-Win64-Shipping.exe";

// GName 的地址 = 模块基址 + 这个偏移
// IDA 里显示 0x144916900，减去 PE 默认基址 0x140000000，就是 0x4916900
static const uint64_t GNAME_OFFSET = 0x4916900;

// 名字表能装多少块、每块多大，完全对应 UE 源码里的 FNameEntryAllocator：
//
//     enum { FNameMaxBlockBits    = 13 };                 // 为什么是 13？见下面注释
//     enum { FNameBlockOffsetBits = 16 };
//     enum { FNameMaxBlocks       = 1 << FNameMaxBlockBits };    // 1 << 13 = 8192
//     enum { FNameBlockOffsets    = 1 << FNameBlockOffsetBits }; // 1 << 16 = 65536
//     enum { Stride = alignof(FNameEntry) };                     // 本作 = 2
//     enum { BlockSizeBytes = Stride * FNameBlockOffsets };      // 2 * 65536 = 0x20000
//
// 用大白话解释：
//   * 每块的大小 = “对齐值” × “每块能放多少个偏移单位”
//        FNameEntry 里有 uint16 头，所以对齐值是 2；
//        偏移单位有 65536 个（正好是 id 低 16 位的取值范围）；
//        所以每块 = 2 * 65536 = 0x20000 字节 = 128KB。
//   * 块的数量上限 = 1 << 13 = 8192。
//        源码注释写的是 “8k * block size = 1GB - 2G of FName entry data”，
//        8192 * 128KB = 1GB，就是名字表最多能占 1GB 内存。
//
// 这里直接按源码的公式写，换版本/换引擎时对照一下就行，不用猜数字。
static const uint32_t FNAME_MAX_BLOCK_BITS    = 13;
static const uint32_t FNAME_BLOCK_OFFSET_BITS = 16;

static const uint32_t BLOCK_COUNT   = 1u << FNAME_MAX_BLOCK_BITS;     // 8192 块
static const uint32_t BLOCK_OFFSETS = 1u << FNAME_BLOCK_OFFSET_BITS;  // 每块 65536 个偏移单位
static const uint32_t STRIDE        = 2;                              // alignof(FNameEntry)
static const uint32_t BLOCK_BYTES   = STRIDE * BLOCK_OFFSETS;         // 0x20000（128KB）

// 遍历时最多打印多少条；0 表示全部（大约 13 万条，会刷很久）
static const int PRINT_LIMIT = 500;

// ============================================================================
//  全局变量：整个程序共用
// ============================================================================

static HANDLE   g_process    = NULL;   // 游戏进程句柄（相当于 C# 的 Process）
static DWORD    g_pid        = 0;      // 进程 ID
static uint64_t g_moduleBase = 0;      // 游戏主模块的基址
static uint64_t g_gname      = 0;      // GName 的地址

// ============================================================================
//  第一步：读内存
// ============================================================================

// 从地址 addr 读 size 个字节，放到 buffer 里。成功返回 true。
static bool ReadBytes(uint64_t addr, void* buffer, uint32_t size)
{
    if (g_process == NULL)
        return false;

    SIZE_T bytesRead = 0;   // SIZE_T 是 Windows 的类型，相当于 nuint

    BOOL ok = ReadProcessMemory(g_process, (LPCVOID)addr, buffer, size, &bytesRead);
    if (ok == FALSE)
        return false;

    return bytesRead == size;
}

// 读 2 字节（ushort）
static uint16_t ReadU16(uint64_t addr)
{
    uint16_t value = 0;
    ReadBytes(addr, &value, 2);
    return value;
}

// 读 4 字节（uint）
static uint32_t ReadU32(uint64_t addr)
{
    uint32_t value = 0;
    ReadBytes(addr, &value, 4);
    return value;
}

// 读 8 字节（ulong，也可以当指针用）
static uint64_t ReadU64(uint64_t addr)
{
    uint64_t value = 0;
    ReadBytes(addr, &value, 8);
    return value;
}

// ============================================================================
//  第二步：找到游戏进程和模块基址
// ============================================================================

// 遍历系统进程列表，按 exe 名字找 PID。找不到返回 0。
static DWORD FindProcessId(const wchar_t* exeName)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W entry;
    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);

    DWORD pid = 0;
    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            if (_wcsicmp(entry.szExeFile, exeName) == 0)   // 忽略大小写比较
            {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return pid;
}

// 在目标进程的模块列表里找 exe 的基址。找不到返回 0。
static uint64_t FindModuleBase(DWORD pid, const wchar_t* moduleName)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    MODULEENTRY32W entry;
    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);

    uint64_t base = 0;
    if (Module32FirstW(snapshot, &entry))
    {
        do
        {
            if (_wcsicmp(entry.szModule, moduleName) == 0)
            {
                base = (uint64_t)entry.modBaseAddr;
                break;
            }
        } while (Module32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return base;
}

// 打开游戏进程并拿到模块基址。全部成功才返回 true。
static bool AttachGame()
{
    g_pid = FindProcessId(GAME_EXE);
    if (g_pid == 0)
        return false;

    g_process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, g_pid);
    if (g_process == NULL)
        return false;

    g_moduleBase = FindModuleBase(g_pid, GAME_EXE);
    return g_moduleBase != 0;
}

// ============================================================================
//  第三步：读一条名字
// ============================================================================

// 一条记录占多少字节：头部 2 字节 + 名字文字，再对齐到 2 字节
static uint32_t EntrySize(uint16_t header)
{
    uint32_t len       = header >> 6;                 // 高 10 位 = 字符数
    uint32_t charBytes = (header & 1) ? 2 : 1;        // 最低位 = 是否 UTF-16

    uint32_t size = 2 + len * charBytes;

    if (size % 2 != 0)      // 奇数就补 1，保证下一条从偶数地址开始
        size = size + 1;

    return size;
}

// UTF-16 转 UTF-8（≈ C# 的 Encoding.UTF8.GetString）
static std::string Utf16ToUtf8(const wchar_t* text, uint32_t length)
{
    if (text == NULL || length == 0)
        return "";

    int bytes = WideCharToMultiByte(CP_UTF8, 0, text, (int)length,
                                    NULL, 0, NULL, NULL);
    if (bytes <= 0)
        return "";

    std::string result;
    result.resize(bytes);

    WideCharToMultiByte(CP_UTF8, 0, text, (int)length, &result[0], bytes, NULL, NULL);
    return result;
}

// 从 entry 地址读一条名字。空条目（块尾）返回空字符串。
// 注意：这个函数只管读一条，不检查“地址在不在块里”，调用方要保证。
static std::string ReadNameAt(uint64_t entry)
{
    uint16_t header = ReadU16(entry);
    uint32_t len    = header >> 6;
    bool     isWide = (header & 1) != 0;

    if (len == 0 || len > 1023)
        return "";      // 空条目，或者长度明显不对

    if (isWide)
    {
        wchar_t buffer[1024];                       // 最多 1023 个字符
        if (!ReadBytes(entry + 2, buffer, len * 2))
            return "";
        return Utf16ToUtf8(buffer, len);
    }
    else
    {
        char buffer[1024];
        if (!ReadBytes(entry + 2, buffer, len))
            return "";
        return std::string(buffer, len);            // 只取 len 个字节
    }
}

// 把 NameId 翻译成名字。失败返回空字符串。
//   number 就是 FName 里的 Number，重复名字会变成 Name_0、Name_1
static std::string GetName(uint32_t nameId, uint32_t number = 0)
{
    // 1) 拆 NameId
    uint32_t blockIndex  = nameId >> 16;        // 第几块
    uint32_t blockOffset = nameId & 0xFFFF;     // 块内偏移（单位：2 字节）

    if (blockIndex >= BLOCK_COUNT)
        return "";

    // 2) 找到这一块的地址
    uint64_t block = ReadU64(g_gname + 0x10 + (uint64_t)blockIndex * 8);
    if (block == 0)
        return "";

    // 3) 算出记录的具体位置：偏移要乘 2 才是字节数
    uint64_t entry = block + (uint64_t)blockOffset * 2;

    // 4) 读名字
    std::string name = ReadNameAt(entry);
    if (name.empty())
        return "";

    // 5) Number > 0 时加后缀（UE 的规则是 Number - 1）
    if (number > 0)
        name = name + "_" + std::to_string(number - 1);

    return name;
}

// ============================================================================
//  第四步：遍历所有块，打印所有名字
// ============================================================================

static void PrintAllNames(int limit)
{
    uint32_t currentBlock = ReadU32(g_gname + 0x08);   // 当前写到第几块
    uint32_t cursor       = ReadU32(g_gname + 0x0C);   // 当前块用了多少字节

    uint64_t total  = 0;
    uint32_t blocks = 0;

    for (uint32_t b = 0; b < BLOCK_COUNT; b++)
    {
        // 1) 取第 b 块的地址；为 0 说明没有更多块了
        uint64_t block = ReadU64(g_gname + 0x10 + (uint64_t)b * 8);
        if (block == 0)
            break;

        blocks++;

        // 2) 这一块到底用了多少字节？
        //    已经写满的块是 BLOCK_BYTES；
        //    但“当前正在写”的那块只用了 cursor 字节，后面是旧内存，
        //    如果照读会把垃圾当成名字。
        uint32_t usedBytes = BLOCK_BYTES;
        if (b == currentBlock && cursor > 0 && cursor <= BLOCK_BYTES)
            usedBytes = cursor;

        // 3) 从块开头一条一条往后走
        uint32_t offset = 0;        // 当前读到了块内第几个字节
        while (offset + 2 <= usedBytes)
        {
            uint16_t header = ReadU16(block + offset);
            uint32_t len    = header >> 6;

            if (len == 0)
                break;              // 块尾的 0，结束了

            uint32_t size = EntrySize(header);
            if (offset + size > usedBytes)
                break;              // 最后一条放不下，也结束

            // 4) 打印（超过 limit 就只数不打印）
            if (limit == 0 || total < (uint64_t)limit)
            {
                std::string name = ReadNameAt(block + offset);
                bool     isWide  = (header & 1) != 0;
                uint32_t id      = (b << 16) | (offset / 2);

                printf("[%6llu] id=0x%08X off=0x%04X len=%3u %c  %s\n",
                       (unsigned long long)total,
                       id,
                       offset,
                       len,
                       isWide ? 'W' : 'A',
                       name.c_str());
            }

            total++;
            offset += size;         // ★ 按这条记录的实际大小前进
        }
    }

    printf("\nTotal: %llu names, %u blocks\n",
           (unsigned long long)total, blocks);
}

// ============================================================================
//  辅助：把一段内存按十六进制打印出来（左边偏移、中间字节、右边字符）
// ============================================================================

static void HexDump(uint64_t addr, int size)
{
    std::vector<uint8_t> buffer(size);       // 相当于 new byte[size]

    if (!ReadBytes(addr, buffer.data(), (uint32_t)size))
    {
        printf("  <read failed>\n");
        return;
    }

    for (int i = 0; i < size; i = i + 16)
    {
        printf("  %04X  ", i);

        // 16 个字节
        for (int j = 0; j < 16; j++)
        {
            if (i + j < size)
                printf("%02X ", buffer[i + j]);
            else
                printf("   ");
        }

        printf("  ");

        // 右边再显示一遍可读字符
        for (int j = 0; j < 16 && i + j < size; j++)
        {
            uint8_t c = buffer[i + j];
            if (c >= 0x20 && c < 0x7F)
                putchar(c);
            else
                putchar('.');
        }

        printf("\n");
    }
}

// 等用户按回车，防止窗口一闪而过
static void Pause()
{
    printf("\nPress Enter to exit...");
    getchar();
}

// ============================================================================
//  main：程序入口（相当于 C# 的 static void Main）
// ============================================================================

int main()
{
    // 让控制台按 UTF-8 显示，否则宽字符名字会是乱码
    SetConsoleOutputCP(CP_UTF8);

    // ── 1. 打开游戏 ────────────────────────────────────────────────────
    if (!AttachGame())
    {
        printf("[-] Attach failed. Is the game running?\n");
        Pause();
        return 1;
    }

    // ── 2. 算出 GName 的地址 ───────────────────────────────────────────
    g_gname = g_moduleBase + GNAME_OFFSET;

    printf("[+] PID         : %lu\n", g_pid);
    printf("[+] Module base : 0x%llX\n", (unsigned long long)g_moduleBase);
    printf("[+] GName       : 0x%llX\n", (unsigned long long)g_gname);

    // ── 3. 检查 Blocks[0] 是否有效 ─────────────────────────────────────
    uint64_t block0 = ReadU64(g_gname + 0x10);
    if (block0 == 0)
    {
        printf("[-] Blocks[0] is 0. Wrong GName offset?\n");
        Pause();
        return 1;
    }

    printf("[+] Blocks[0]   : 0x%llX\n", (unsigned long long)block0);

    // ── 4. 打印 Block[0] 开头，用眼睛确认一下 ──────────────────────────
    // 正常应该能看到 "None" 和 "ByteProperty"
    printf("\n--- Block 0, first 0x80 bytes ---\n");
    HexDump(block0, 0x80);

    // ── 5. 试几个已知 NameId ───────────────────────────────────────────
    // 这几个名字是引擎启动时固定插入的，顺序通常不会变
    printf("\n--- Try some known ids ---\n");

    uint32_t knownIds[9] = { 0x00, 0x03, 0x0A, 0x11, 0x18, 0x20, 0x28, 0x2F, 0x38 };
    for (int i = 0; i < 9; i++)
    {
        uint32_t id = knownIds[i];
        std::string name = GetName(id);

        if (name.empty())
            printf("  id=0x%08X -> <invalid>\n", id);
        else
            printf("  id=0x%08X -> %s\n", id, name.c_str());
    }

    // ── 6. 遍历整个名字表 ──────────────────────────────────────────────
    printf("\n--- List names (limit = %d) ---\n", PRINT_LIMIT);
    PrintAllNames(PRINT_LIMIT);

    // ── 7. 收尾 ────────────────────────────────────────────────────────
    CloseHandle(g_process);     // 用完记得关（C++ 没有 GC）
    g_process = NULL;

    Pause();
    return 0;
}
