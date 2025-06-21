#define _CRT_SECURE_NO_WARNINGS
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")
#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <string.h>
#include <string.h>


//Decryption function
int decrypt_file() {
    int ch;
    FILE* input, * output;
    char input_file[256];
    char output_file[256];



    unsigned char inputkey[65] = { 0 };
    unsigned char key[32] = { 0 };
    int len, i, j;

    //Enter the hexadecimal key
    printf("Please enter the key: \n");
re1:
    scanf("%64s", inputkey);
    while ((ch = getchar()) != '\n' && ch != EOF);

    size_t l = strlen(inputkey);
    if (l != 64) {
        printf("The key must be a 64 bit hexadecimal number, please enter the key again: \n");
        goto re1;
    }

    //Convert the string corresponding to the hexadecimal key to a 256-bit binary key (stored in 64 bytes)
    j = 0;
    for (i = 0; i < 64; i += 2) {
        sscanf(inputkey + i, "%2hhX", &key[j]);
        j++;
    }


    printf("Please enter the file name that needs to be decrypted: \n");
    scanf("%255[^\n]", input_file); //Use "% [^ n]" to ensure that all characters, including spaces, are read until "\ n"
    while ((ch = getchar()) != '\n' && ch != EOF);

    printf("After the file is decrypted, a decrypted file will be generated. Please name it: \n");
name1:    
    scanf("%255[^\n]", output_file);
    while ((ch = getchar()) != '\n' && ch != EOF);
    for (int k = 0; k < 256; k++) {
        if (output_file[k] != input_file[k]) {
            break;
        }
        if (k == 255) {
            printf("The output file cannot be named the same as the input file. Please rename it again:\n");
            goto name1;
        }
    }
    
    input = fopen(input_file, "rb");
    if (input == NULL) {
        perror("An error occurred while opening the file that needs to be decrypted");
        return -1;
    }

    output = fopen(output_file, "wb");
    if (output == NULL) {
        fclose(input);
        perror("An error occurred while generating the decrypted file");
        return -1;
    }

    //Read the initial vector IV from the beginning of the file
    unsigned char iv[AES_BLOCK_SIZE];
    if (fread(iv, 1, AES_BLOCK_SIZE, input) != AES_BLOCK_SIZE) {
        printf("Error: Unable to read IV, probably the file is corrupted.\n");
        fclose(input);
        fclose(output);
        return -1;
    }

    //Initialize decryption operation
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fclose(input);
        fclose(output);
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(input);
        fclose(output);
        return -1;
    }

    //Input and output buffers
    unsigned char inbuf[1024];
    unsigned char outbuf[1024 + AES_BLOCK_SIZE];

    int inlen, outlen;

    //Read the file in a loop, and then perform the decryption operation
    while ((inlen = fread(inbuf, 1, sizeof(inbuf), input)) > 0) {
        if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(input);
            fclose(output);
            return -1;
        }
        fwrite(outbuf, 1, outlen, output);
    }

    //Process the final data block and padding, then write it to the file
    if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(input);
        fclose(output);
        return -1;
    }
    fwrite(outbuf, 1, outlen, output);

    EVP_CIPHER_CTX_free(ctx);
    printf("The decrypted file has been generated: %s\n",&output_file);
    fclose(input);
    fclose(output);
    return 0;
}

//Encryption function
int encrypt_file() {

    int ch;
    FILE* input, * output;
    char input_file[256] = { 0 };
    char output_file[256] = { 0 };


    unsigned char inputkey[65] = { 0 };
    unsigned char key[32] = { 0 };
    int len, i, j;

    //Enter the hexadecimal key
    printf("Please enter the key: \n");
re2:
    scanf("%64s", inputkey);
    while ((ch = getchar()) != '\n' && ch != EOF);

    size_t l = strlen(inputkey);
    if (l != 64) {
        printf("The key must be a 64 bit hexadecimal number, please enter the key again: \n");
        goto re2;
    }

    j = 0;
    for (i = 0; i < 64; i += 2) {
        sscanf(inputkey + i, "%2hhX", &key[j]);
        j++;
    }


    printf("Please enter the file name that needs to be encrypted: \n");
    scanf("%255[^\n]", input_file);
    while ((ch = getchar()) != '\n' && ch != EOF);

    printf("After the file is encrypted, an encrypted file will be generated. Please name it: \n");
name2:
    scanf("%255[^\n]", output_file);
    while ((ch = getchar()) != '\n' && ch != EOF);
    for (int k = 0; k < 256; k++) {
        if (output_file[k] != input_file[k]) {
            break;
        }
        if (k == 255) {
            printf("The output file cannot be named the same as the input file. Please rename it again:\n");
            goto name2;
        }
    }

    input = fopen(input_file, "rb");
    if (input == NULL) {
        perror("An error occurred while opening the file that needs to be encrypted");
        return -1;
    }

    output = fopen(output_file, "wb");
    if (output == NULL) {
        fclose(input);
        perror("An error occurred while generating the encrypted file");
        return -1;
    }

    unsigned char iv[AES_BLOCK_SIZE];
    if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) {
        printf("Failed to generate random IV.\n");
        fclose(input);
        fclose(output);
        return -1;
    }

    //Write IV at the beginning of the ciphertext file
    fwrite(iv, 1, AES_BLOCK_SIZE, output);

    //Initialize decryption
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fclose(input);
        fclose(output);
        return -1;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(input);
        fclose(output);
        return -1;
    }

    //input and output buffer
    unsigned char inbuf[1024];
    unsigned char outbuf[1024 + AES_BLOCK_SIZE];

    int inlen, outlen;

    //Read and encrypt file data in a loop
    while ((inlen = fread(inbuf, 1, sizeof(inbuf), input)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(input);
            fclose(output);
            return -1;
        }
        fwrite(outbuf, 1, outlen, output);
    }

    //Processing the last data block and handling padding
    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(input);
        fclose(output);
        return -1;
    }
    fwrite(outbuf, 1, outlen, output);

    EVP_CIPHER_CTX_free(ctx);
    printf("The encrypted file has been generated: %s\n", &output_file);
    fclose(input);
    fclose(output);
    return 0;
}



int main() {
    int ch;

    unsigned char key[32];
menu:

    ;
    int op=0;
    printf("Please enter a number to select an operation (press Enter to confirm): \n1. Encrypt \n2. Decrypt \n3. Generate a new key \n4. Safely clear the key and exit\n");
re0:
    scanf_s("%1d", &op);
    while ((ch = getchar()) != '\n' && ch != EOF);
    switch (op) {
    case 1:

        if (encrypt_file() == -1) {
            printf("Encryption failed.\n");
            
        }
        else {
            printf("File encryption successful!\n");
        }
        break;


    case 2:

        if (decrypt_file() == -1) {
            printf("Decryption failed.\n");
            
        }
        else {
            printf("File decryption successful!\n");
        }
        break;
    case 3:
        if (RAND_status() != 1) {
            fprintf(stderr, "Warning: The random number generator has insufficient entropy and is attempting to replenish it. Suggest generating a new key\n");
            RAND_poll(); //Supplement entropy to ensure that the random number generator has sufficient entropy to generate safe random numbers
        }
        if (RAND_priv_bytes(key, sizeof(key)) != 1) {    //Generate unpredictable random bytes using OpenSSL's cryptographic secure pseudo-random number generator
            fprintf(stderr, "Key generation failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
            break;
        }
        printf("A randomly generated key: \n");
        for (int i = 0; i < 32; i++) {
            printf("%02x", key[i]);
        }
        printf("\n");
        break;
    case 4:
        OPENSSL_cleanse(key, sizeof(key));//Clear the key from memory, otherwise it cannot be guaranteed that this data will be immediately and completely erased from physical memory
        exit(0);
        break;
    default:
        printf("Input error, please re-enter: \n");
        goto re0;
        break;
    }
    goto menu;
    return 0;
}
