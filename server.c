#include <stdio.h>
#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/stat.h>   // Needed for mkdir()
#include <sys/types.h>  // Needed for mkdir()

#define SERVER_PORT 4444
#define BUFFER_SIZE 4096
#define DEST_IP "192.168.1.79"

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    // Замените на путь к вашим сертификатам
    const char *cert_path = "cert.pem";
    const char *key_path = "key.pem";

    if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void receive_file(SSL *ssl) {
    int name_len;
    SSL_read(ssl, &name_len, sizeof(int));

    char filename[name_len + 1];
    SSL_read(ssl, filename, name_len);
    filename[name_len] = '\0';

    // Construct the full path with the "downloads" directory
    char full_path[512];
    snprintf(full_path, sizeof(full_path), "downloads/%s", filename);

    long file_size;
    SSL_read(ssl, &file_size, sizeof(long));

    FILE *file = fopen(full_path, "wb");
    if (!file) {
        perror("Failed to open file for writing");
        return;
    }

    char buffer[BUFFER_SIZE];
    int bytes_read;
    while (file_size > 0) {
        bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes_read <= 0) {
            ERR_print_errors_fp(stderr);
            fclose(file);
            return;
        }
        fwrite(buffer, 1, bytes_read, file);
        file_size -= bytes_read;
    }

    fclose(file);
    char ack[4] = "ACK";
    SSL_write(ssl, ack, sizeof(ack));  // Send acknowledgment
}

void ensure_directory_exists(const char *dir_name) {
    struct stat st = {0};
    if (stat(dir_name, &st) == -1) {
        mkdir(dir_name, 0755);
    }
}


int main() {
    ensure_directory_exists("downloads");

    libnet_t *l;  // Дескриптор библиотеки
    char errbuf[LIBNET_ERRBUF_SIZE];

    // Инициализация библиотеки
    l = libnet_init(LIBNET_LINK, "en0", errbuf);
    if (l == NULL) {
        fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
        return 1;
    }

    uint8_t dst_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t src_mac[6] = {0x01, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD};

    uint32_t src_ip = libnet_get_ipaddr4(l);
    if (src_ip == -1) {
        fprintf(stderr, "Error getting IP address: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        exit(1);
    }

    // IP-адрес назначения
    uint32_t dst_ip = libnet_name2addr4(l, DEST_IP, LIBNET_RESOLVE);

    //uint32_t custom_payload = htonl(1337);
    const char *custom_payload_str = "macip";
    size_t custom_payload_size = strlen(custom_payload_str) + 1;
    // Создание ARP-запроса
    libnet_ptag_t arp = libnet_build_arp(
        ARPHRD_ETHER,       // Тип аппаратного адреса
        ETHERTYPE_IP,       // Тип протокольного адреса
        6,                  // Длина аппаратного адреса
        4,                  // Длина протокольного адреса
        ARPOP_REQUEST,      // Операция ARP
        src_mac,            // MAC-адрес отправителя
        (uint8_t *)&src_ip, // IP-адрес отправителя
        dst_mac,            // MAC-адрес назначения
        (uint8_t *)&dst_ip, // IP-адрес назначения
        (uint8_t *)custom_payload_str,               // Полезная нагрузка
        custom_payload_size,
        //sizeof(custom_payload),                  // Длина полезной нагрузки
        l,                  // Дескриптор библиотеки
        0                   // ptag
    );

    if (arp == -1) {
        fprintf(stderr, "Ошибка при создании ARP-запроса: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        return 1;
    }

    // Создание Ethernet-заголовка
    libnet_ptag_t eth = libnet_build_ethernet(
        dst_mac,            // MAC-адрес назначения
        src_mac,            // MAC-адрес отправителя
        ETHERTYPE_ARP,      // Тип протокола
        NULL,               // Полезная нагрузка
        0,                  // Длина полезной нагрузки
        l,                  // Дескриптор библиотеки
        0                   // ptag
    );

    printf("Используемый интерфейс: %s\n", libnet_getdevice(l));

    if (eth == -1) {
        fprintf(stderr, "Ошибка при создании Ethernet-заголовка: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        return 1;
    }

    // Отправка пакета
    if (libnet_write(l) == -1) {
        fprintf(stderr, "Ошибка при отправке пакета: %s\n", libnet_geterror(l));
    }
    else {
        printf("ARP-пакет отправлен");
    }

    // Освобождение ресурсов
    libnet_destroy(l);

    init_openssl();
    SSL_CTX *ctx = create_context();
    configure_context(ctx);

    int server = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(server, (struct sockaddr*)&addr, sizeof(addr));
    listen(server, 5);

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client = accept(server, (struct sockaddr*)&client_addr, &client_len);

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client);
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    int file_count;
    SSL_read(ssl, &file_count, sizeof(int));

    for (int i = 0; i < file_count; i++) {
        receive_file(ssl);
    }

    SSL_free(ssl);
    close(client);
    close(server);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}
