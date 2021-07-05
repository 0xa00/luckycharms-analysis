/* Definitions For Includes */
#define WIN32_LEAN_AND_MEAN

/* Includes */
#include <Windows.h>
#include <winternl.h>
#include <strsafe.h>
#include <stdio.h>

/* Definitions */
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define MEMORY_BUFFER_CLEAR -1
#define MEMORY_BUFFER_CREATE -2
#define MAX_MEMORY_BUFFERS 7

/* Libraries */
#pragma comment(lib, "ntdll.lib")

/* Definitions */
NTSTATUS NTAPI NtWriteVirtualMemory(IN  HANDLE ProcessHandle,
                                     OUT PVOID BaseAddress,
                                     IN  PVOID Buffer,
                                     IN  ULONG BufferSize,
                                     OUT PULONG NumberOfBytesWritten OPTIONAL);

//
// Get a process handle to any running process named "csgo.exe"
//
HANDLE LlFindProcess(
        PWSTR szImageName,
        unsigned int uImageNameLength
);

//
// Write the authentication data file
//
BOOL LlWriteAuthenticationData();

//
// Reads the memory buffer for an index
//
PVOID LlGetMemoryBuffer(
        INT Index,
        DWORD Size
);
#define MEMORY_BUFFER_INDEX(I, S) ((PVOID)LlGetMemoryBuffer(I, S)), S
static HANDLE heapMemoryBuffers = NULL;
static PVOID arrAllocatedMemoryBuffers[MAX_MEMORY_BUFFERS] = { 0 };

INT main(INT nArgs, PCHAR* arrArgs)
{
    PWSTR szImageName = L"csgo.exe";
    //
    // Attempt to get a handle to any running process with the matching image name
    //
    HANDLE pProcess = LlFindProcess(szImageName, lstrlenW(szImageName));

    //
    // Process was not found or OpenProcess() failed, exit with failure
    //
    if (pProcess == NULL)
        return EXIT_FAILURE;
    wprintf(L"[+] Got a handle (szImageName=%s)", szImageName);

    //
    // Write the authentication data for the library to read
    //
    if (LlWriteAuthenticationData() == FALSE)
        return EXIT_FAILURE;
    printf("\n[+] Wrote authentication data");

    //
    // Allocate memory buffer heap
    //
    if (LlGetMemoryBuffer(MEMORY_BUFFER_CREATE, 0ul) == NULL)
        return EXIT_FAILURE;
    printf("\n[*] Allocated memory buffer heap");

    LPVOID pLibraryBlock = VirtualAllocEx(pProcess, NULL, 1011712ul, 12288, 64);
    NtWriteVirtualMemory(pProcess, pLibraryBlock, MEMORY_BUFFER_INDEX(0, 1024ul), NULL);
    NtWriteVirtualMemory(pProcess, (PVOID)((PCHAR)pLibraryBlock + 4096), MEMORY_BUFFER_INDEX(1, 665600ul), NULL);
    NtWriteVirtualMemory(pProcess, (PVOID)((PCHAR)pLibraryBlock + 671744), MEMORY_BUFFER_INDEX(2, 124928ul), NULL);
    NtWriteVirtualMemory(pProcess, (PVOID)((PCHAR)pLibraryBlock + 798720), MEMORY_BUFFER_INDEX(3, 24576ul), NULL);
    NtWriteVirtualMemory(pProcess, (PVOID)((PCHAR)pLibraryBlock + 954368), MEMORY_BUFFER_INDEX(4, 10240ul), NULL);
    NtWriteVirtualMemory(pProcess, (PVOID)((PCHAR)pLibraryBlock + 966656), MEMORY_BUFFER_INDEX(5, 512ul), NULL);
    NtWriteVirtualMemory(pProcess, (PVOID)((PCHAR)pLibraryBlock + 970752), MEMORY_BUFFER_INDEX(6, 40448ul), NULL);
    CHAR lpReserved[24], shellcode[256];
    HANDLE hFile = CreateFileA("ldata\\lpReserved.ldata", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (ReadFile(hFile, lpReserved, 24, NULL, NULL) == FALSE)
        return EXIT_FAILURE;
    CloseHandle(hFile);
    hFile = CreateFileA("ldata\\shellcode.ldata", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (ReadFile(hFile, shellcode, 256, NULL, NULL) == FALSE)
        return EXIT_FAILURE;
    CloseHandle(hFile);
    LPVOID pShellcodeBlock = VirtualAllocEx(pProcess, NULL, 4096ul, 12288, 64);
    NtWriteVirtualMemory(pProcess, pShellcodeBlock, lpReserved, 24, NULL);
    PVOID pShellcodeAddr = (PVOID)((PCHAR)pShellcodeBlock + 24);
    NtWriteVirtualMemory(pProcess, pShellcodeAddr, shellcode, 256, NULL);
    printf("\n[*] Executing shellcode");
    CreateRemoteThread(pProcess, NULL, 0ull, (LPTHREAD_START_ROUTINE)pShellcodeAddr, pShellcodeBlock, 0, 0);
    //
    // Free the memory buffer heap
    //
    if (LlGetMemoryBuffer(MEMORY_BUFFER_CLEAR, 0ul) == NULL)
        printf("\n[-] warning: Failed to clear memory buffers");
    wprintf(L"\n[*] Shellcode executed in '%s'", szImageName);

    return EXIT_SUCCESS;
}

PVOID LlGetMemoryBuffer(INT Index, DWORD Size)
{
    if (Index == MEMORY_BUFFER_CLEAR)
    {
        if (heapMemoryBuffers == NULL)
            return NULL;
        for (int i = 0; i < 7; i++) {
            PVOID Block = arrAllocatedMemoryBuffers[i];
            if (Block == NULL)
                continue;
            HeapFree(heapMemoryBuffers, 0, Block);
        }
        HeapDestroy(heapMemoryBuffers);
        return (PVOID) TRUE;
    }
    else if (Index == MEMORY_BUFFER_CREATE)
    {
        if ((heapMemoryBuffers = HeapCreate(0ul, 0ul, 1024 * 1024)) == NULL)
            return NULL;
        return (PVOID) TRUE;
    }
    if (Index > MAX_MEMORY_BUFFERS)
        return NULL;
    PVOID Block = HeapAlloc(heapMemoryBuffers, HEAP_ZERO_MEMORY, Size);
    arrAllocatedMemoryBuffers[Index] = Block;
    CHAR szFileName[64];
    sprintf_s(szFileName, 64, "ldata\\l%d.bin", Index);
    HANDLE hFile = CreateFileA(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (ReadFile(hFile, Block, Size, NULL, NULL) == FALSE)
        return NULL;
    CloseHandle(hFile);
    return NULL;
}

BOOL LlWriteAuthenticationData()
{
    CHAR Path[MAX_PATH + 1], Dest[MAX_PATH + 1];
    //
    // Get AppData/Temp directory path.
    // This can be replaced by SHGetKnownFolderPath, but this is simpler and doesn't require the use of shells.
    //
    if (GetEnvironmentVariableA("TEMP", Path, MAX_PATH + 1) == FALSE)
        return FALSE;
    //
    // Append the authentication file path
    //
    sprintf_s(Dest, MAX_PATH + 1, "%s\\qwieovnuoiq\\tkUAEpEhiDV2NHk", Path);
    //
    // Copy the files
    //
    if (CopyFileA("ldata\\auth.ldata", Dest, FALSE) == FALSE)
        return FALSE;
    return TRUE;
}

HANDLE LlFindProcess(PWSTR szImageName, unsigned int uImageNameLength)
{
    HANDLE ProcessHandle = NULL;
    DWORD ReturnSize;
    //
    // Find the size of the process list
    //
    NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &ReturnSize);
    if (ReturnSize == 0ul)
        return NULL;

    //
    // Allocate the process list buffer
    //
    PVOID Block = VirtualAlloc(NULL, ReturnSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (Block == NULL)
        return NULL;

    //
    // Populate the process list buffer
    //
    PSYSTEM_PROCESS_INFORMATION SystemProcessInfo = (PSYSTEM_PROCESS_INFORMATION) Block;
    if (!NT_SUCCESS(NtQuerySystemInformation(SystemProcessInformation, SystemProcessInfo, ReturnSize, NULL)))
        goto Exit;

    PSYSTEM_PROCESS_INFORMATION CurrentProcess = SystemProcessInfo;
    while (TRUE)
    {
        if (CurrentProcess->ImageName.Length == uImageNameLength * sizeof(WCHAR))
        {
            if (!wcsncmp(szImageName, CurrentProcess->ImageName.Buffer, CurrentProcess->ImageName.Length / sizeof(WCHAR))) {
                break;
            }
        }
        CurrentProcess = (PSYSTEM_PROCESS_INFORMATION) ((LPBYTE) CurrentProcess + CurrentProcess->NextEntryOffset);
        if (!CurrentProcess->NextEntryOffset)
            goto Exit;
    }

    //
    // Get a handle to the found process
    //
    ProcessHandle = OpenProcess
            (
                    PROCESS_CREATE_THREAD |
                    PROCESS_QUERY_INFORMATION |
                    PROCESS_VM_READ |
                    PROCESS_VM_WRITE |
                    PROCESS_VM_OPERATION,

                    FALSE,

                    (DWORD) CurrentProcess->UniqueProcessId
            );

    goto Exit;
    Exit:
    VirtualFree(Block, ReturnSize, MEM_RELEASE);
    return ProcessHandle;
}
