#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <unordered_map>

typedef NTSTATUS (NTAPI *pNtQueryInformationThread)(
    HANDLE,
    ULONG,
    PVOID,
    ULONG,
    PULONG
);

struct ModuleInfo {
    uintptr_t base;
    uintptr_t end;
    std::string name;
};
struct ThreadInfo {
    DWORD tid;
    uintptr_t startAddress;
};

//module enumeration.....
std::vector<ModuleInfo> GetModules(DWORD pid) {

    std::vector<ModuleInfo> modules;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE)
        return modules;

    MODULEENTRY32 me;
    me.dwSize = sizeof(me);

    if (Module32First(snapshot, &me)) {
        do {
            uintptr_t base = (uintptr_t)me.modBaseAddr;
            uintptr_t end  = base + me.modBaseSize;

            modules.push_back({
                base,
                end,
                me.szModule
            });

        } while (Module32Next(snapshot, &me));
    }

    CloseHandle(snapshot);
    return modules;
}
bool IsAddressInModule(uintptr_t addr, const std::vector<ModuleInfo>& modules) {

    for (const auto& m : modules) {
        if (addr >= m.base && addr < m.end) {
            return true;
        }
    }

    return false;
}
// ---------------- THREAD ENUMERATION ----------------
std::vector<ThreadInfo> GetThreads(DWORD pid, pNtQueryInformationThread NtQueryInformationThread) {
    std::vector<ThreadInfo> threads;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return threads;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    if (Thread32First(snapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(
                    THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
                    FALSE,
                    te.th32ThreadID
                );

                if (hThread) {
                    PVOID startAddress = 0;

                    if (NtQueryInformationThread(
                            hThread,
                            9,
                            &startAddress,
                            sizeof(startAddress),
                            NULL
                        ) == 0) {

                        threads.push_back({
                            te.th32ThreadID,
                            (uintptr_t)startAddress
                        });
                    }

                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(snapshot, &te));
    }

    CloseHandle(snapshot);
    return threads;
}

// ---------------- MEMORY SCAN ----------------
void ScanProcess(DWORD pid, pNtQueryInformationThread NtQueryInformationThread) {

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess)
        return;

    std::vector<ThreadInfo> threads = GetThreads(pid, NtQueryInformationThread);
    std::vector<ModuleInfo> modules = GetModules(pid);

    MEMORY_BASIC_INFORMATION mbi;
    unsigned char* address = 0;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {

        DWORD protect = mbi.Protect;

        bool isExecutable =
            protect & PAGE_EXECUTE ||
            protect & PAGE_EXECUTE_READ ||
            protect & PAGE_EXECUTE_READWRITE ||
            protect & PAGE_EXECUTE_WRITECOPY;

        if (mbi.State == MEM_COMMIT &&
            mbi.Type == MEM_PRIVATE &&
            isExecutable) {

            uintptr_t base = (uintptr_t)mbi.BaseAddress;
            uintptr_t end  = base + mbi.RegionSize;

            int count = 0;

            for (auto& t : threads) {
                if (t.startAddress >= base && t.startAddress < end) {
                    bool inModule = IsAddressInModule(t.startAddress, modules);

                    if (!inModule) {
                        count++;

                        std::cout<< " executing OUTSIDE module (VERY SUSPICIOUS)\n";
                        }
                    std::cout << "[!] PID " << pid
                              << " Thread " << t.tid
                              << " executing in suspicious region\n";
                }
            }

            if (count > 0) {
                std::cout << "---- Suspicious Region ----\n";
                std::cout << "PID: " << pid << "\n";
                std::cout << "Base: " << mbi.BaseAddress << "\n";
                std::cout << "Size: " << mbi.RegionSize << "\n";
                std::cout << "Threads: " << count << "\n";
                std::cout << "---------------------------\n";
            }
        }

        address += mbi.RegionSize;
    }

    CloseHandle(hProcess);
}

// ---------------- MAIN ----------------
int main() {

    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtDll) {
        std::cout << "Failed to load ntdll\n";
        return 1;
    }

    pNtQueryInformationThread NtQueryInformationThread =
        (pNtQueryInformationThread)GetProcAddress(hNtDll, "NtQueryInformationThread");

    if (!NtQueryInformationThread) {
        std::cout << "Failed to resolve NtQueryInformationThread\n";
        return 1;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to create process snapshot\n";
        return 1;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    if (Process32First(snapshot, &pe)) {
        do {
            DWORD pid = pe.th32ProcessID;

            // Skip idle/system
            if (pid == 0 || pid == 4)
                continue;

            ScanProcess(pid, NtQueryInformationThread);

        } while (Process32Next(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return 0;
}