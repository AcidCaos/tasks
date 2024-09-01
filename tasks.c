#include <stdio.h>
#include <Windows.h>
#include <psapi.h> // Process Status API (PSAPI)
#include <winternl.h> // NtQueryInformationProcess

// https://learn.microsoft.com/en-us/windows/win32/psapi/enumerating-all-processes

int main()
{
    // Get a list of PIDs
    DWORD aProcesses[1024], cbNeeded, cProcesses;

    if ( !EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded) )
    {
        printf( "Enumerating Processes failed\r\n" );
        return 1;
    }

    wprintf(L"PID\tPPID\tPRIO\tDBG\tNAME\n\r");
    for (DWORD i = 0; i < cbNeeded / sizeof(DWORD); i++)
    {
        DWORD processID = aProcesses[i];

        if( processID == 0 )
        {
            continue;
        }

        // Get process handle
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
        
        if (hProcess == NULL)
        {
            continue;
        }

        // Array of module handles. We only need one: typically, the first module in the array represents the executable file that started the process.
        HMODULE hMod[1];
        DWORD cbNeeded;

        // This function is used to enumerate the loaded modules within the process, and it fills an array with the module handles.
        if ( !EnumProcessModules(hProcess, hMod, sizeof(hMod), &cbNeeded) )
        {
            CloseHandle( hProcess );
            continue;
        }

        wchar_t wProcessName[MAX_PATH];

        // Get the process name. The first module (hMod[0]) should represent the executable file that started the process.
        if ( !GetModuleBaseNameW(hProcess, hMod[0], wProcessName, sizeof(wProcessName) / sizeof(wchar_t)) )
        {
            CloseHandle( hProcess );
            continue;
        }

        // Get the process information

        // https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
        // The NtQueryInformationProcess() function does not have an import library, so we must use run-time dynamic linking to access this function in ntdll.dll

        typedef struct _PROCESS_BASIC_INFORMATION {
            NTSTATUS ExitStatus;
            PPEB PebBaseAddress;
            ULONG_PTR AffinityMask;
            KPRIORITY BasePriority;
            ULONG_PTR UniqueProcessId;
            ULONG_PTR InheritedFromUniqueProcessId;
        } PROCESS_BASIC_INFORMATION;

        // PROCESS_INFORMATION_CLASS 
        typedef enum _PROCESSINFOCLASS {
            ProcessBasicInformation = 0, // Retrieves a pointer to a PEB structure that can be used to determine whether the specified process is being debugged, and a unique value used by the system to identify the specified process.
            ProcessDebugPort = 7, // Retrieves a DWORD_PTR value that is the port number of the debugger for the process. A nonzero value indicates that the process is being run under the control of a ring 3 debugger.
            ProcessWow64Information = 26, // Determines whether the process is running in the WOW64 environment (WOW64 is the x86 emulator that allows Win32-based applications to run on 64-bit Windows).
            ProcessImageFileName = 27, // Retrieves a UNICODE_STRING value containing the name of the image file for the process.
            ProcessBreakOnTermination = 29, // Retrieves a ULONG value indicating whether the process is considered critical.
            ProcessTelemetryIdInformation = 64, // Retrieves a PROCESS_TELEMETRY_ID_INFORMATION_TYPE value that contains metadata about a process.
            ProcessSubsystemInformation = 75, // Retrieves a SUBSYSTEM_INFORMATION_TYPE value indicating the subsystem type of the process. The buffer pointed to by the ProcessInformation parameter should be large enough to hold a single SUBSYSTEM_INFORMATION_TYPE enumeration. 
            // ...
        } PROCESSINFOCLASS;

        typedef NTSTATUS (NTAPI *fNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
        fNtQueryInformationProcess NtQueryInformationProcess;
        

        // No need to load the library, as ntdll is already loaded in every process
        // HMODULE hNtDll = LoadLibraryW(L"ntdll.dll");
        // NtQueryInformationProcess = (fNtQueryInformationProcess) GetProcAddress(hNtDll, "NtQueryInformationProcess");
        NtQueryInformationProcess = (fNtQueryInformationProcess) GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
        
        if ( NtQueryInformationProcess == NULL )
        {
            CloseHandle( hProcess );
            continue;
        }

        PROCESS_BASIC_INFORMATION pbi;
        if ( NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL) != 0 )
        {
            CloseHandle( hProcess );
            continue;
        }

        DWORD parentProcessID;
        parentProcessID = (DWORD)pbi.InheritedFromUniqueProcessId;

        DWORD processPriority;
        processPriority = (DWORD)pbi.BasePriority;

        BYTE beingDebugged;
        ReadProcessMemory(hProcess, &pbi.PebBaseAddress->BeingDebugged, &beingDebugged, sizeof(BYTE), NULL);
        wchar_t debugger;
        debugger = (beingDebugged) ? L'D' : L' ';

        wprintf(L"%u\t%u\t%u\t%c\t%s\n", processID, parentProcessID, processPriority, debugger, wProcessName);

        CloseHandle( hProcess );
    }
    return 0;
}