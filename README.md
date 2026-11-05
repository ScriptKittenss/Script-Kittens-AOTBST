# Script Kittens AOTBST

Hypervisor bridge DLL for the Script Kittens Internal Panel. It gives `Client.dll` raw physical memory access to the Free Fire guest running inside BlueStacks, by hooking VirtualBox memory manager — then hides itself.

## How it works

1. **Hardens itself first** — hides its thread from debuggers (`NtSetInformationThread`) and blinds ETW (`EtwEventWrite` → `RET`).
2. **Finds BlueStacks VMM** — resolves `BstkVMM.dll` and its exports (`PGMPhysRead`, `PGMPhysSimpleWriteGCPhys`, `PGMPhysGCPtr2GCPhys`, `VMMGetCpuById`) by walking the PEB manually. No `GetProcAddress`, no plaintext strings — every name is a hash, every string is XOR-encrypted at compile time.
3. **Captures the VM pointer** — hooks the physical read/write with MinHook for ~3 seconds, just long enough to catch the VM instance the first time VirtualBox calls them, then removes the hooks immediately.
4. **Hands off to the cheat** — loads `Client.dll` from the same folder and calls its `Load(vmInstancePtr)`.
5. **Erases itself** — zeroes its own PE headers and unlinks itself from all three PEB loader lists. `Client.dll` already cached the function pointers, so it is safe.

## Exports

Used by `Client.dll` and the C# app:

| Export | What it does |
| --- | --- |
| `CPU(pVM, cpuId)` | Get a vCPU handle |
| `InternalRead(pVM, address, buffer, size)` | Read guest physical memory |
| `Cast(pVCpu, address, &physAddress)` | Translate a guest address to a physical address |
| `InternalWrite(pVM, address, buffer, size)` | Write guest physical memory |

## Files

| File | What it is |
| --- | --- |
| `ScriptKittensDllMain.cpp` | The bridge: hardening, VMM hook, handoff, self-erase |
| `PEBWalk.h` | Manual PEB module/export resolution (no winternl.h) |
| `XorStr.h` | Compile-time XOR string encryption |
| `ScriptKittensInternalMemory.cs` | C# wrapper (`AotForms`) — `Read<T>`, `ReadArray`, `ReadString`, `Write<T>`, with an address cache |
| `Minhook/` | MinHook hooking library (vendored) |

## Build

1. Open `ScriptKittens.sln` in Visual Studio 2022+.
2. Build **x64 / Release**.
3. Output: `ScriptKittens.dll` — place it next to `Client.dll`.
