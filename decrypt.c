#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ENCRYPTION_KEY "my_secret_key"  // Replace with your actual encryption key

char xor_decrypt_char(char ch, size_t *key_index) {
    const size_t key_len = strlen(ENCRYPTION_KEY);
    char decrypted = ch ^ ENCRYPTION_KEY[*key_index];
    *key_index = (*key_index + 1) % key_len;  // Increment key index and wrap around
    return decrypted;
}

void decrypt_log_file(const char *encrypted_log_path, const char *decrypted_log_path) {
    FILE *file = fopen(encrypted_log_path, "rb");
    if (file == NULL) {
        perror("Failed to open encrypted log file");
        exit(EXIT_FAILURE);
    }

    FILE *out_file = fopen(decrypted_log_path, "wb");
    if (out_file == NULL) {
        perror("Failed to open decrypted log file for writing");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    char ch;
    size_t key_index = 0;  // Initialize key index
    while ((ch = fgetc(file)) != EOF) {
        char decrypted_char = xor_decrypt_char(ch, &key_index);
        if (fputc(decrypted_char, out_file) == EOF) { // Write the decrypted character to the output file
            perror("Failed to write to decrypted log file");
            fclose(file);
            fclose(out_file);
            return;
        }

        if (decrypted_char == '\n') {
            key_index = 0;  // Reset key index for new line
        } 
    }

    fclose(file);
    fclose(out_file);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <encrypted_log_path> <decrypted_log_path>\n", argv[0]);
        return EXIT_FAILURE;
    }
    decrypt_log_file(argv[1], argv[2]);
    return EXIT_SUCCESS;
}
