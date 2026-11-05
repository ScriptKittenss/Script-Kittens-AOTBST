#include <Windows.h>
#include <string>
#include <filesystem>
#include "Minhook/include/MinHook.h"
#include "PEBWalk.h"
#include "XorStr.h"

// ═══════════════════════════════════════════════════════════════════
//  ScriptKittens.dll — Hardened Hypervisor Bridge
//  ALL strings encrypted. ALL imports resolved via PEB walk.
//  PE headers erased. PEB unlinked. Thread hidden.
// ═══════════════════════════════════════════════════════════════════

typedef int(__cdecl* PGMPhysReadType)(void*, uintptr_t, void*, size_t);
typedef int(__cdecl* PGMPhysSimpleWriteGCPhysType)(void*, uintptr_t, void*, size_t);
typedef int(__cdecl* PGMPhysGCPtr2GCPhysType)(void*, uintptr_t, uintptr_t*);
typedef void* (__cdecl* VMMGetCpuByIdType)(void*, int);

static PGMPhysReadType physRead = nullptr;
static PGMPhysReadType originalPhysRead = nullptr;

static PGMPhysSimpleWriteGCPhysType physWrite = nullptr;
static PGMPhysSimpleWriteGCPhysType originalPhysWrite = nullptr;

static PGMPhysGCPtr2GCPhysType physConvert = nullptr;
static VMMGetCpuByIdType physCpu = nullptr;
static inline void* vmInstancePtr = nullptr;

// ── Interop hooks (transient — only live ~3 seconds) ──
static int InteropPhysRead(void* vmInstance, uintptr_t physAddress, void* buffer, size_t bufferSize)
{
    if (!vmInstancePtr) vmInstancePtr = vmInstance;
    return originalPhysRead(vmInstance, physAddress, buffer, bufferSize);
}

static int InteropPhysWrite(void* vmInstance, uintptr_t physAddress, void* buffer, size_t bufferSize)
{
    if (!vmInstancePtr) vmInstancePtr = vmInstance;
    return originalPhysWrite(vmInstance, physAddress, buffer, bufferSize);
}

// ── Exports (called by Client.dll via PEBWalk) ──
extern "C" __declspec(dllexport)
void* __stdcall CPU(void* pVM, int cpuId)
{
    if (!pVM) return nullptr;
    return physCpu(pVM, cpuId);
}

extern "C" __declspec(dllexport)
int __stdcall InternalRead(void* pVM, uintptr_t address, void* buffer, size_t size)
{
    if (!pVM) return -1;
    return physRead(pVM, address, buffer, size);
}

extern "C" __declspec(dllexport)
int __stdcall Cast(void* pVCpu, uintptr_t address, uintptr_t* physAddress)
{
    if (!pVCpu || !physAddress) return -1;
    return physConvert(pVCpu, address, physAddress);
}

extern "C" __declspec(dllexport)
int __stdcall InternalWrite(void* pVM, uintptr_t address, void* buffer, size_t size)
{
    if (!pVM) return -1;
    return physWrite(pVM, address, buffer, size);
}

// ── Security: Erase PE headers of this DLL ──
static void ErasePE(HMODULE hMod)
{
    if (!hMod) return;
    DWORD old = 0;
    if (VirtualProtect((LPVOID)hMod, 0x1000, PAGE_READWRITE, &old))
    {
        SecureZeroMemory((LPVOID)hMod, 0x1000);
        VirtualProtect((LPVOID)hMod, 0x1000, PAGE_NOACCESS, &old);
    }
}

// ── Security: Unlink this DLL from PEB (all 3 LDR lists) ──
static void UnlinkPEB(HMODULE hSelf)
{
    if (!hSelf) return;
#ifdef _WIN64
    SK_PEB* peb = (SK_PEB*)__readgsqword(0x60);
#else
    SK_PEB* peb = (SK_PEB*)__readfsdword(0x30);
#endif
    LIST_ENTRY* head = &peb->Ldr->InLoadOrderModuleList;
    LIST_ENTRY* curr = head->Flink;
    while (curr != head)
    {
        SK_LDR_DATA_TABLE_ENTRY* e =
            CONTAINING_RECORD(curr, SK_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (e->DllBase == hSelf)
        {
            e->InLoadOrderLinks.Blink->Flink           = e->InLoadOrderLinks.Flink;
            e->InLoadOrderLinks.Flink->Blink           = e->InLoadOrderLinks.Blink;
            e->InMemoryOrderLinks.Blink->Flink         = e->InMemoryOrderLinks.Flink;
            e->InMemoryOrderLinks.Flink->Blink         = e->InMemoryOrderLinks.Blink;
            e->InInitializationOrderLinks.Blink->Flink = e->InInitializationOrderLinks.Flink;
            e->InInitializationOrderLinks.Flink->Blink = e->InInitializationOrderLinks.Blink;
            if (e->BaseDllName.Buffer)
                SecureZeroMemory(e->BaseDllName.Buffer, e->BaseDllName.MaximumLength);
            if (e->FullDllName.Buffer)
                SecureZeroMemory(e->FullDllName.Buffer, e->FullDllName.MaximumLength);
            break;
        }
        curr = curr->Flink;
    }
}

// ── Security: Hide thread from debuggers ──
typedef LONG(NTAPI* NtSetInfoThread)(HANDLE, ULONG, PVOID, ULONG);
static void HideThread()
{
    constexpr uint32_t hNtdll = PEB::Hash(L"ntdll.dll");
    constexpr uint32_t hNtSet = PEB::HashA("NtSetInformationThread");
    auto fn = (NtSetInfoThread)PEB::Resolve(hNtdll, hNtSet);
    if (fn) fn(GetCurrentThread(), 0x11 /*ThreadHideFromDebugger*/, nullptr, 0);
}

// ── Security: Blind ETW telemetry ──
static void BlindETW()
{
    constexpr uint32_t hNtdll = PEB::Hash(L"ntdll.dll");
    constexpr uint32_t hEtw   = PEB::HashA("EtwEventWrite");
    uint8_t* fn = (uint8_t*)PEB::Resolve(hNtdll, hEtw);
    if (!fn) return;
    DWORD old = 0;
    if (VirtualProtect(fn, 1, PAGE_EXECUTE_READWRITE, &old))
    {
        *fn = 0xC3; // RET
        VirtualProtect(fn, 1, old, &old);
    }
}

// ── Initialize: Hook BstkVMM, capture VM pointer ──
static bool Initialize()
{
    // Resolve BstkVMM.dll via PEB walk — no plaintext string in import table
    constexpr uint32_t hVMM = PEB::Hash(L"bstkvmm.dll");
    HMODULE bstkVMM = PEB::GetModule(hVMM);
    if (!bstkVMM) return false;

    // Resolve exports via PEB walk — no GetProcAddress calls
    constexpr uint32_t hPhysRead    = PEB::HashA("PGMPhysRead");
    constexpr uint32_t hPhysWrite   = PEB::HashA("PGMPhysSimpleWriteGCPhys");
    constexpr uint32_t hPhysConvert = PEB::HashA("PGMPhysGCPtr2GCPhys");
    constexpr uint32_t hPhysCpu     = PEB::HashA("VMMGetCpuById");

    physRead    = (PGMPhysReadType)              PEB::GetExport(bstkVMM, hPhysRead);
    physWrite   = (PGMPhysSimpleWriteGCPhysType) PEB::GetExport(bstkVMM, hPhysWrite);
    physConvert = (PGMPhysGCPtr2GCPhysType)      PEB::GetExport(bstkVMM, hPhysConvert);
    physCpu     = (VMMGetCpuByIdType)             PEB::GetExport(bstkVMM, hPhysCpu);

    if (!physRead || !physWrite || !physConvert || !physCpu) return false;

    if (MH_Initialize() != MH_OK) return false;

    if (MH_CreateHook((LPVOID)physRead, InteropPhysRead, (LPVOID*)&originalPhysRead) != MH_OK) return false;
    if (MH_EnableHook((LPVOID)physRead) != MH_OK) return false;

    if (MH_CreateHook((LPVOID)physWrite, InteropPhysWrite, (LPVOID*)&originalPhysWrite) != MH_OK)
    {
        MH_DisableHook((LPVOID)physRead);
        return false;
    }
    if (MH_EnableHook((LPVOID)physWrite) != MH_OK)
    {
        MH_DisableHook((LPVOID)physRead);
        return false;
    }

    // Wait up to 3s for VirtualBox to naturally call PGMPhysRead/Write
    constexpr int TIMEOUT_MS = 3000;
    int elapsed = 0;
    while (vmInstancePtr == nullptr && elapsed < TIMEOUT_MS)
    {
        Sleep(10);
        elapsed += 10;
    }

    // Remove hooks immediately — transient only
    MH_DisableHook((LPVOID)physRead);
    MH_DisableHook((LPVOID)physWrite);
    MH_Uninitialize();

    return vmInstancePtr != nullptr;
}

typedef void (*LoadFunc)(void* pVM);

static bool LoadPayload(HMODULE hModule)
{
    // Build path to Client.dll from our own directory
    char buffer[MAX_PATH];
    DWORD length = GetModuleFileNameA(hModule, buffer, MAX_PATH);
    std::string DllPath;
    if (length)
        DllPath = std::filesystem::path(buffer).parent_path().string() + XS("\\Client.dll");
    else
        return false;

    HMODULE hClient = LoadLibraryA(DllPath.c_str());
    if (!hClient) return false;

    // Resolve Load export via PEB walk — not GetProcAddress
    constexpr uint32_t hClientMod = PEB::Hash(L"client.dll");
    constexpr uint32_t hLoadExport = PEB::HashA("Load");
    HMODULE hCl = PEB::GetModule(hClientMod);
    if (!hCl) hCl = hClient;

    LoadFunc Load = (LoadFunc)PEB::GetExport(hCl, hLoadExport);
    if (!Load)
    {
        FreeLibrary(hClient);
        return false;
    }

    if (Initialize())
    {
        Load(vmInstancePtr);
    }

    return true;
}

static DWORD WINAPI InitThread(LPVOID lpParam)
{
    HMODULE hSelf = (HMODULE)lpParam;

    // ── Security hardening BEFORE doing anything visible ──
    HideThread();
    BlindETW();

    // Load payload (Client.dll) and start cheat
    if (!LoadPayload(hSelf))
    {
        FreeLibraryAndExitThread(hSelf, 1);
    }

    // Erase our PE headers + unlink from PEB AFTER Client.dll has resolved our exports
    // Client.dll's Mem::Init() already cached our function pointers via PEB walk,
    // so it's safe to destroy our PE and PEB entry now.
    ErasePE(hSelf);
    UnlinkPEB(hSelf);

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, InitThread, hModule, 0, NULL);
    }
    return TRUE;
}
