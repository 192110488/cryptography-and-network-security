#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl.h>

void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; ++i) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

void encrypt_cbc_3des(const unsigned char *plaintext, const unsigned char *key, const unsigned char *iv, size_t plaintext_len) {
    DES_cblock des_key1, des_key2, des_key3;
    DES_key_schedule ks1, ks2, ks3;

    // Split the 24-byte key into three separate 8-byte DES keys
    memcpy(des_key1, key, 8);
    memcpy(des_key2, key + 8, 8);
    memcpy(des_key3, key + 16, 8);

    DES_set_key(&des_key1, &ks1);
    DES_set_key(&des_key2, &ks2);
    DES_set_key(&des_key3, &ks3);

    DES_cblock ivec;
    memcpy(ivec, iv, sizeof(ivec));

    // Perform encryption
    size_t block_size = DES_BLOCK_SIZE;
    unsigned char* encrypted_data = (unsigned char*)malloc(plaintext_len);
    DES_ede3_cbc_encrypt(plaintext, encrypted_data, plaintext_len, &ks1, &ks2, &ks3, &ivec, DES_ENCRYPT);

    print_hex("Encrypted data", encrypted_data, plaintext_len);

    free(encrypted_data);
}

int main() {
    const unsigned char plaintext[] = "Hello, CBC 3DES Encryption!";
    const unsigned char key[] = "sOmE_KeY_For_3DES_Encryption";
    const unsigned char iv[] = "IV_IV_IV"; // Initialization Vector

    printf("Plaintext: %s\n", plaintext);

    size_t plaintext_len = strlen((const char *)plaintext);

    printf("Plaintext Length: %zu\n", plaintext_len);

    encrypt_cbc_3des(plaintext, key, iv, plaintext_len);

    return 0;
}

