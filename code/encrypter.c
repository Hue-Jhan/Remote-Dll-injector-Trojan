#include <Windows.h>
#include <stdio.h>
#include <string.h>

void xor_encrypt(unsigned char* data, int length, unsigned char key) {
    for (int i = 0; i < length; i++) {
        data[i] ^= key;
    }
}

const char* base64_chars = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba0987654321+/";

void base64_encode(unsigned char* data, int length, char* output) {
    int i = 0, enc_len = 0;
    unsigned char char_array_3[3], char_array_4[4];
    while (length--) {
        char_array_3[i++] = *(data++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            for (i = 0; i < 4; i++) {
                output[enc_len++] = base64_chars[char_array_4[i]];
            }
            i = 0;
        }
    }

    if (i) {
        for (int j = i; j < 3; j++) {
            char_array_3[j] = '\0';
        }
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        for (int k = 0; k < i + 1; k++) {
            output[enc_len++] = base64_chars[char_array_4[k]];
        }
        while ((i++ < 3)) {
            output[enc_len++] = '=';
        }
    }
    output[enc_len] = '\0';
}

void hex_encode(unsigned char* data, int length, char* output) {
    for (int i = 0; i < length; i++) {
        sprintf(output + (i * 2), "%02x", data[i]);
    }
    output[length * 2] = '\0';
}

int main() {
    unsigned char shellcode[] =
    "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xcc\x00\x00\x00\x41"
    "\x51\x41\x50\x52\x48\x31\xd2\x51\x65\x48\x8b\x52\x60\x48"
    "\x8b\x52\x18\x56\x48\x8b\x52\x20\x48\x0f\xb7\x4a\x4a\x48"
    "\x8b\x72\x50\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02"
    "\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x48\x8b"
    "\x52\x20\x8b\x42\x3c\x48\x01\xd0\x41\x51\x66\x81\x78\x18"
    "\x0b\x02\x0f\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00"
    "\x48\x85\xc0\x74\x67\x48\x01\xd0\x44\x8b\x40\x20\x49\x01"
    "\xd0\x8b\x48\x18\x50\xe3\x56\x4d\x31\xc9\x48\xff\xc9\x41"
    "\x8b\x34\x88\x48\x01\xd6\x48\x31\xc0\x41\xc1\xc9\x0d\xac"
    "\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39"
    "\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b"
    "\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x41"
    "\x58\x48\x01\xd0\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41"
    "\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
    "\x8b\x12\xe9\x4b\xff\xff\xff\x5d\xe8\x0b\x00\x00\x00\x75"
    "\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00\x59\x41\xba\x4c"
    "\x77\x26\x07\xff\xd5\x49\xc7\xc1\x40\x00\x00\x00\xe8\x03"
    "\x00\x00\x00\x58\x44\x00\x5a\xe8\x03\x00\x00\x00\x58\x44"
    "\x00\x41\x58\x48\x31\xc9\x41\xba\x45\x83\x56\x07\xff\xd5"
    "\x48\x31\xc9\x41\xba\xf0\xb5\xa2\x56\xff\xd5";

    // shellcode for messagebox that says "xd"
    
    size_t shellcode_length = sizeof(shellcode) - 1;
    char base64_encoded[4096];
    base64_encode(shellcode, shellcode_length, base64_encoded);

    printf("Base64 Encoded Shellcode:\n%s\n\n", base64_encoded);

    xor_encrypt((unsigned char*)base64_encoded, strlen(base64_encoded), 0xAA);

    printf("XOR Encrypted Base64 (Hex):\n");
    char hex_output[8192];
    hex_encode((unsigned char*)base64_encoded, strlen(base64_encoded), hex_output);
    printf("%s\n", hex_output);

    return 0;
}
