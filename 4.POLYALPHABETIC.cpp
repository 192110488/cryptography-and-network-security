#include <stdio.h>
#include <string.h>

// Function to encrypt a message using the Vigenere cipher
void vigenereEncrypt(const char *key, const char *message, char *cipher) {
    int keyLength = strlen(key);
    int messageLength = strlen(message);

    for (int i = 0; i < messageLength; i++) {
        if (message[i] != ' ') {
            // Shift the current character by the corresponding key character
            cipher[i] = 'A' + (message[i] + key[i]) % 26;
        } else {
            // Preserve spaces in the message
            cipher[i] = ' ';
        }
    }

    // Null-terminate the cipher string
    cipher[messageLength] = '\0';
}

int main() {
    char key[100];
    char message[100];
    char cipher[100];

    // Step 1: Enter the key
    printf("Enter the key: ");
    scanf("%s", key);

    // Step 2: Enter the message to be encrypted
    printf("Enter the message to be encrypted: ");
    scanf(" %[^\n]s", message);

    // Step 3: Encrypt the message using the Vigenere cipher
    vigenereEncrypt(key, message, cipher);

    // Step 4: Display the encrypted message
    printf("Encrypted message: %s\n", cipher);

    return 0;
}
