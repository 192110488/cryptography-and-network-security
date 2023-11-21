#include <stdio.h>
#include <string.h>

// Function to generate the Playfair key table
void generateKeyTable(char key[5][5], const char *keystr) {
    char *keystring = strdup(keystr);
    char *ptr = keystring;
    char keytable[5][5];
    int i, j, k;
    char alphabet[26] = "ABCDEFGHIKLMNOPQRSTUVWXYZ";

    // Remove duplicate letters from the key
    for (i = 0; i < strlen(keystring); i++) {
        if (keystring[i] == 'J')
            keystring[i] = 'I';
        for (j = i + 1; j < strlen(keystring); j++) {
            if (keystring[j] == keystring[i]) {
                for (k = j; k < strlen(keystring); k++)
                    keystring[k] = keystring[k + 1];
            }
        }
    }

    // Fill the key table with the key
    k = 0;
    for (i = 0; i < 5; i++) {
        for (j = 0; j < 5; j++) {
            if (k < strlen(keystring))
                keytable[i][j] = keystring[k++];
            else {
                int exists = 0;
                while (strchr(keystring, alphabet[exists]) != NULL)
                    exists++;
                keytable[i][j] = alphabet[exists++];
            }
        }
    }

    // Display the key table
    printf("Playfair Key Table:\n");
    for (i = 0; i < 5; i++) {
        for (j = 0; j < 5; j++) {
            printf("%c ", keytable[i][j]);
        }
        printf("\n");
    }

    // Copy the key table to the output parameter
    for (i = 0; i < 5; i++)
        for (j = 0; j < 5; j++)
            key[i][j] = keytable[i][j];

    
}

// Function to find the positions of two characters in the key table
void findPosition(char key[5][5], char ch, int *row, int *col) {
    int i, j;
    for (i = 0; i < 5; i++)
        for (j = 0; j < 5; j++)
            if (key[i][j] == ch) {
                *row = i;
                *col = j;
            }
}

// Function to encrypt a pair of characters using the Playfair cipher
void encryptPair(char key[5][5], char a, char b, char *cipher) {
    int row1, col1, row2, col2;
    findPosition(key, a, &row1, &col1);
    findPosition(key, b, &row2, &col2);

    if (row1 == row2) {
        cipher[0] = key[row1][(col1 + 1) % 5];
        cipher[1] = key[row2][(col2 + 1) % 5];
    } else if (col1 == col2) {
        cipher[0] = key[(row1 + 1) % 5][col1];
        cipher[1] = key[(row2 + 1) % 5][col2];
    } else {
        cipher[0] = key[row1][col2];
        cipher[1] = key[row2][col1];
    }
}

// Function to encrypt a message using the Playfair cipher
void encryptMessage(char key[5][5], const char *message, char *cipher) {
    int len = strlen(message);
    int i;
    for (i = 0; i < len; i += 2) {
        char a = message[i];
        char b = (i + 1 < len) ? message[i + 1] : 'X';
        encryptPair(key, a, b, cipher + i);
    }
}

int main() {
    char key[5][5];
    char message[100];
    char cipher[100];

    // Step 1: Enter the key
    printf("Enter the key: ");
    scanf("%s", message);

    // Step 2: Generate the key table
    generateKeyTable(key, message);

    // Step 3: Enter the message to be encrypted
    printf("Enter the message to be encrypted: ");
    scanf("%s", message);

    // Step 4: Encrypt the message
    encryptMessage(key, message, cipher);

    // Step 5: Display the encrypted message
    printf("Encrypted message: %s\n", cipher);

    return 0;
}
