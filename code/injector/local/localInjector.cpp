#include <windows.h>
#include <stdio.h>

DWORD WINAPI threadFunc(LPVOID lpParam) {
	printf("Thread is running...\n");
  // ...
	return 0;
}


int main(int argc, char** argv) {
	PCSTR path_to_dll = argv[1];
	HINSTANCE hDll = LoadLibraryA(argv[1]);
	if (hDll == NULL) {
		printf("Failed to load DLL.\n");
		return 1;
	}

	HANDLE hThread = CreateThread(NULL, 0, threadFunc, NULL, 0, NULL);
	if (hThread == NULL) {
		printf("Failed to create thread: %d\n", GetLastError());
		return 1;
	}

  WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	FreeLibrary(hDll);

	return 0;
}
