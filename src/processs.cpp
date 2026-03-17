#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <iomanip>


typedef NTSTATUS (NTAPI *pNtQueryInformationThread)(
    HANDLE,
    ULONG,
    PVOID,
    ULONG,
    PULONG
);


DWORD GetProcessIdByName(const wchar_t* processName) {
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (!_wcsicmp(pe.szExeFile, processName)) {
                CloseHandle(snapshot);
                return pe.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return 0;
}

const char* GetProtect(DWORD protect) {
    switch (protect) {
        case PAGE_EXECUTE: return "EXECUTE";
        case PAGE_EXECUTE_READ: return "EXECUTE_READ";
        case PAGE_EXECUTE_READWRITE: return "EXECUTE_READWRITE";
        case PAGE_READONLY: return "READONLY";
        case PAGE_READWRITE: return "READWRITE";
        default: return "OTHER";
    }
}

const char* GetType(DWORD type) {
    switch (type) {
        case MEM_IMAGE: return "MEM_IMAGE";
        case MEM_MAPPED: return "MEM_MAPPED";
        case MEM_PRIVATE: return "MEM_PRIVATE";
        default: return "UNKNOWN";
    }
}

int CountThreadsInRegion(DWORD pid, LPVOID regionBase, SIZE_T regionSize)
{
    int suspiciousThreadCount = 0;

    // Load NtQueryInformationThread
    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtDll)
        return 0;

    pNtQueryInformationThread NtQueryInformationThread =
        (pNtQueryInformationThread)GetProcAddress(
            hNtDll,
            "NtQueryInformationThread"
        );

    if (!NtQueryInformationThread)
        return 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    if (Thread32First(snapshot, &te))
    {
        do
        {
            if (te.th32OwnerProcessID == pid)
            {
                HANDLE hThread = OpenThread(
                    THREAD_QUERY_INFORMATION,
                    FALSE,
                    te.th32ThreadID
                );

                if (hThread)
                {
                    PVOID startAddress = 0;

                    NTSTATUS status = NtQueryInformationThread(
                        hThread,
                        9, // ThreadQuerySetWin32StartAddress
                        &startAddress,
                        sizeof(startAddress),
                        NULL
                    );

                    if (status == 0)
                    {
                        uintptr_t start = (uintptr_t)startAddress;
                        uintptr_t base  = (uintptr_t)regionBase;
                        uintptr_t end   = base + regionSize;

                        if (start >= base && start < end)
                        {
                            suspiciousThreadCount++;

                            std::cout << "[!] Thread "
                                      << te.th32ThreadID
                                      << " starts inside suspicious region\n";
                        }
                    }

                    CloseHandle(hThread);
                }
            }

        } while (Thread32Next(snapshot, &te));
    }

    CloseHandle(snapshot);
    return suspiciousThreadCount;
}
int main() {

    DWORD pid = GetProcessIdByName(L"notepad.exe");
    if (!pid) {
        std::cout << "Notepad not running.\n";
        return 1;
    }

    std::cout << "PID: " << pid << "\n";

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        std::cout << "Failed to open process.\n";
        return 1;
    }

    MEMORY_BASIC_INFORMATION mbi;
    unsigned char* address = 0;

    std::cout << std::left << std::setw(18) << "BaseAddress"
              << std::setw(12) << "Size"
              << std::setw(15) << "Type"
              << std::setw(20) << "Protection"
              << "\n";

    // while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {

    //     std::cout << std::left
    //               << std::setw(18) << mbi.BaseAddress
    //               << std::setw(12) << mbi.RegionSize
    //               << std::setw(15) << GetType(mbi.Type)
    //               << std::setw(20) << GetProtect(mbi.Protect)
    //               << "\n";

    //     address += mbi.RegionSize;
    // }
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {

    DWORD protect = mbi.Protect & 0xFF;  // mask modifiers

    bool isExecutable =
        protect == PAGE_EXECUTE ||
        protect == PAGE_EXECUTE_READ ||
        protect == PAGE_EXECUTE_READWRITE ||
        protect == PAGE_EXECUTE_WRITECOPY;

    if (mbi.State == MEM_COMMIT &&
        mbi.Type == MEM_PRIVATE &&
        isExecutable) {

        std::cout << "[!] Suspicious Region Found\n";
        std::cout << "Base Address : " << mbi.BaseAddress << "\n";
        std::cout << "Size         : " << mbi.RegionSize << "\n";
        std::cout << "Protection   : " << GetProtect(protect) << "\n";
        int count = CountThreadsInRegion(pid, mbi.BaseAddress,mbi.RegionSize);
        std::cout << "Total threads executing from region: "
          << count << std::endl;
        std::cout << "--------------------------------------\n";
    }

    address += mbi.RegionSize;
}

    CloseHandle(hProcess);
    return 0;
}