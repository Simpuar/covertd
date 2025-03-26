#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ENCRYPTION_KEY "my_secret_key"

char *xor_encrypt(const char *input, size_t len) {
    const size_t key_len = strlen(ENCRYPTION_KEY);
    char *encrypted = (char *)malloc(len + 1); // Allocate one extra for null-terminator

    if (!encrypted) {
        perror("Memory allocation failed");
        return NULL;
    }

    for (size_t i = 0; i < len; ++i) {
        encrypted[i] = input[i] ^ ENCRYPTION_KEY[i % key_len];
    }
    encrypted[len] = '\0'; // Null-terminate the encrypted string

    return encrypted;
}

void decrypt_ppm_file(const char *encrypted_file_path, const char *decrypted_file_path) {
    FILE *encrypted_file = fopen(encrypted_file_path, "rb");
    if (!encrypted_file) {
        perror("Unable to open encrypted file");
        return;
    }

    // Get the size of the encrypted file
    fseek(encrypted_file, 0, SEEK_END);
    size_t encrypted_size = ftell(encrypted_file);
    fseek(encrypted_file, 0, SEEK_SET);

    // Read the encrypted data into a buffer
    char *encrypted_data = malloc(encrypted_size);
    if (!encrypted_data) {
        fclose(encrypted_file);
        perror("Memory allocation failed");
        return;
    }
    fread(encrypted_data, 1, encrypted_size, encrypted_file);
    fclose(encrypted_file);

    // Decrypt the data using the same xor_encrypt function
    char *decrypted_data = xor_encrypt(encrypted_data, encrypted_size);
    free(encrypted_data); // Free the encrypted data buffer

    if (!decrypted_data) {
        perror("Decryption failed");
        return;
    }

    // Write the decrypted data to a new file
    FILE *decrypted_file = fopen(decrypted_file_path, "wb");
    if (!decrypted_file) {
        free(decrypted_data);
        perror("Unable to open decrypted file for writing");
        return;
    }
    size_t written = fwrite(decrypted_data, 1, encrypted_size, decrypted_file);
    if (written != encrypted_size) {
        fprintf(stderr, "Error: Only %zu out of %zu bytes were written.\n", written, encrypted_size);
        fclose(decrypted_file);
        free(decrypted_data);
        return;
    } 
    else {
        printf("Decrypted file saved as: %s\n", decrypted_file_path);
    }

    fclose(decrypted_file);
    free(decrypted_data);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <encrypted_file_path> <decrypted_file_base_path>\n", argv[0]);
        return 1;
    }

    const char *encrypted_file_path = argv[1];
    char decrypted_file_path[1024];

    snprintf(decrypted_file_path, sizeof(decrypted_file_path), "%s.ppm", argv[2]);

    decrypt_ppm_file(encrypted_file_path, decrypted_file_path);

    return 0;
}

