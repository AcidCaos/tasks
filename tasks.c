#include <stdio.h>
#include <Windows.h>
#include <psapi.h> // Process Status API (PSAPI)

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

    wprintf(L"PID\tNAME\n\r");
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

        wprintf(L"%u\t%s\n", processID, wProcessName);
        
        CloseHandle( hProcess );
    }
    return 0;
}