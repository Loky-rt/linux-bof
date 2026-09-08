// gcc -c -o krb_listccaches.o krb_listccaches.c -include bof_api.h -Os -fPIC

#include "bof_api.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PROCESSED 64

static uint32_t read_be32(char *data, int offset) {
    return ((unsigned char)data[offset] << 24) | 
           ((unsigned char)data[offset+1] << 16) | 
           ((unsigned char)data[offset+2] << 8) | 
           (unsigned char)data[offset+3];
}

static uint16_t read_be16(char *data, int offset) {
    return ((unsigned char)data[offset] << 8) | 
           (unsigned char)data[offset+1];
}

static char g_processed[MAX_PROCESSED][1024];
static int g_processed_count = 0;

static int is_duplicate(const char *path) {
    char resolved[1024];

    if (AxRealpath(path, resolved)) {
        for (int i = 0; i < g_processed_count; i++) {
            if (AxStrcmp(g_processed[i], resolved) == 0) {
                return 1; // Duplicado
            }
        }

        if (g_processed_count < MAX_PROCESSED) {
            AxStrncpy(g_processed[g_processed_count], resolved, 1023);
            g_processed[g_processed_count][1023] = '\0';
            g_processed_count++;
        }
    }

    return 0;
}

// Función para leer un string del buffer
static int read_string_at(char *data, int *offset, int max_len, char *out, int out_cap) {
    if (*offset + 4 > max_len) return -1;

    uint32_t len = read_be32(data, *offset);
    *offset += 4;

    if (*offset + len > max_len) return -1;
    if (len >= out_cap) return -1;

    AxMemcpy(out, data + *offset, len);
    out[len] = '\0';
    *offset += len;

    return 0;
}

static int read_principal_at(char *data, int *offset, int max_len, char *out_name, int out_cap) {
    if (*offset + 4 > max_len) return -1;
    uint32_t name_type = read_be32(data, *offset);
    *offset += 4;

    if (*offset + 4 > max_len) return -1;
    uint32_t num_components = read_be32(data, *offset);
    *offset += 4;

    char realm[256];
    if (read_string_at(data, offset, max_len, realm, sizeof(realm)) != 0) {
        return -1;
    }

    char name[1024];
    name[0] = '\0';

    for (uint32_t i = 0; i < num_components && i < 10; i++) {
        char component[256];
        if (read_string_at(data, offset, max_len, component, sizeof(component)) != 0) {
            return -1;
        }

        if (AxStrlen(name) > 0) AxStrcat(name, "/");
        AxStrcat(name, component);
    }

    if (AxStrlen(name) > 0) AxStrcat(name, "@");
    AxStrcat(name, realm);

    AxStrncpy(out_name, name, out_cap - 1);
    out_name[out_cap - 1] = '\0';

    return 0;
}

static void format_time(uint32_t timestamp, char *out, int out_size) {
    if (timestamp == 0) {
        AxSnprintf(out, out_size, "N/A");
        return;
    }

    uint32_t days = timestamp / 86400;
    uint32_t years = 1970;
    uint32_t rem_days = days;

    while (1) {
        uint32_t days_in_year = 365;
        if ((years % 4 == 0 && years % 100 != 0) || (years % 400 == 0)) {
            days_in_year = 366;
        }

        if (rem_days < days_in_year) break;
        rem_days -= days_in_year;
        years++;
    }

    static const uint32_t month_days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    static const char *month_names[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    uint32_t month = 0;
    for (month = 0; month < 12; month++) {
        uint32_t days_in_month = month_days[month];
        if (month == 1 && ((years % 4 == 0 && years % 100 != 0) || (years % 400 == 0))) {
            days_in_month = 29;
        }

        if (rem_days < days_in_month) break;
        rem_days -= days_in_month;
    }

    uint32_t day = rem_days + 1;
    uint32_t hour = (timestamp % 86400) / 3600;
    uint32_t minute = (timestamp % 3600) / 60;
    uint32_t second = timestamp % 60;

    AxSnprintf(out, out_size, "%s %02u %u %02u:%02u:%02u", 
               month_names[month], day, years, hour, minute, second);
}

// Función para parsear un archivo .ccache
static void parse_ccache_file(const char *path, int *count) {
    // Verificar duplicado
    if (is_duplicate(path)) {
        return;
    }

    char *data = NULL;
    int size = AxReadFileToBuffer(path, &data, 1048576);

    if (size <= 0 || !data) return;

    int offset = 0;

    if (offset + 2 > size) {
        AxFree(data);
        return;
    }
    uint16_t version = read_be16(data, offset);
    offset += 2;

    if (offset + 2 > size) {
        AxFree(data);
        return;
    }
    uint16_t header_len = read_be16(data, offset);
    offset += 2;

    offset += header_len;

    char cache_principal[1024];
    if (read_principal_at(data, &offset, size, cache_principal, sizeof(cache_principal)) != 0) {
        AxFree(data);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n");
    BeaconPrintf(CALLBACK_OUTPUT, "┌─ Ticket Cache ─────────────────────────────────\n");
    BeaconPrintf(CALLBACK_OUTPUT, "│ Type:      FILE\n");
    BeaconPrintf(CALLBACK_OUTPUT, "│ Name:      %s\n", path);
    BeaconPrintf(CALLBACK_OUTPUT, "│ Principal: %s\n", cache_principal);
    BeaconPrintf(CALLBACK_OUTPUT, "│ Version:   %d\n", version);

    int cred_count = 0;
    while (offset < size) {
        char client[1024];
        if (read_principal_at(data, &offset, size, client, sizeof(client)) != 0) break;

        char server[1024];
        if (read_principal_at(data, &offset, size, server, sizeof(server)) != 0) break;

        if (offset + 2 > size) break;
        uint16_t enctype = read_be16(data, offset);
        offset += 2;

        char key_data[512];
        if (read_string_at(data, &offset, size, key_data, sizeof(key_data)) != 0) break;

        if (offset + 16 > size) break;
        uint32_t authtime = read_be32(data, offset);
        uint32_t starttime = read_be32(data, offset + 4);
        uint32_t endtime = read_be32(data, offset + 8);
        uint32_t renew_till = read_be32(data, offset + 12);
        offset += 16;

        if (offset + 1 > size) break;
        offset += 1;

        if (offset + 4 > size) break;
        offset += 4;

        if (offset + 4 > size) break;
        uint32_t num_addresses = read_be32(data, offset);
        offset += 4;

        for (uint32_t i = 0; i < num_addresses && i < 10; i++) {
            if (offset + 4 > size) break;
            offset += 4;
            char addr_data[256];
            if (read_string_at(data, &offset, size, addr_data, sizeof(addr_data)) != 0) break;
        }

        if (offset + 4 > size) break;
        uint32_t num_authdata = read_be32(data, offset);
        offset += 4;

        for (uint32_t i = 0; i < num_authdata && i < 10; i++) {
            if (offset + 4 > size) break;
            offset += 4;
            char auth_data[512];
            if (read_string_at(data, &offset, size, auth_data, sizeof(auth_data)) != 0) break;
        }

        char ticket_data[4096];
        if (read_string_at(data, &offset, size, ticket_data, sizeof(ticket_data)) != 0) break;

        char second_ticket[4096];
        if (read_string_at(data, &offset, size, second_ticket, sizeof(second_ticket)) != 0) break;

        cred_count++;

        BeaconPrintf(CALLBACK_OUTPUT, "│\n");
        BeaconPrintf(CALLBACK_OUTPUT, "│   [%d] Service: %s\n", cred_count, server);
        BeaconPrintf(CALLBACK_OUTPUT, "│       Client:  %s\n", client);
        BeaconPrintf(CALLBACK_OUTPUT, "│       Enctype: %d\n", enctype);

        char auth_str[64], start_str[64], end_str[64];
        format_time(authtime, auth_str, sizeof(auth_str));
        format_time(starttime, start_str, sizeof(start_str));
        format_time(endtime, end_str, sizeof(end_str));

        BeaconPrintf(CALLBACK_OUTPUT, "│       Auth:  %s\n", auth_str);
        BeaconPrintf(CALLBACK_OUTPUT, "│       Start: %s\n", start_str);
        BeaconPrintf(CALLBACK_OUTPUT, "│       End:   %s\n", end_str);

        if (renew_till > 0) {
            char renew_str[64];
            format_time(renew_till, renew_str, sizeof(renew_str));
            BeaconPrintf(CALLBACK_OUTPUT, "│       Renew: %s\n", renew_str);
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "└────────────────────────────────────────────────\n");

    AxFree(data);
    (*count)++;
}

// Buscar archivos .ccache en un directorio recursivamente
static void search_dir_recursive(const char *dir_path, int depth, int *count) {
    if (depth > 3) return;

    int dir_fd = AxOpenDir(dir_path);
    if (dir_fd < 0) return;

    char buf[8192];
    int n;

    while ((n = AxReadDir(dir_fd, buf, sizeof(buf))) > 0) {
        for (int offset = 0; offset < n;) {
            unsigned long d_ino;
            unsigned long d_off;
            unsigned short d_reclen;
            unsigned char d_type;
            char d_name[256];

            AxMemcpy(&d_ino, buf + offset, sizeof(d_ino));
            AxMemcpy(&d_off, buf + offset + 8, sizeof(d_off));
            AxMemcpy(&d_reclen, buf + offset + 16, sizeof(d_reclen));
            d_type = buf[offset + 18];

            int name_len = 0;
            for (int i = 0; i < d_reclen - 19 && offset + 19 + i < n; i++) {
                d_name[i] = buf[offset + 19 + i];
                if (d_name[i] == '\0') {
                    name_len = i;
                    break;
                }
            }
            d_name[name_len] = '\0';

            if (d_name[0] == '.' && (d_name[1] == '\0' || (d_name[1] == '.' && d_name[2] == '\0'))) {
                offset += d_reclen;
                continue;
            }

            char full_path[1024];
            AxSnprintf(full_path, sizeof(full_path), "%s/%s", dir_path, d_name);

            if (d_type == 8) {
                if (AxStrstr(d_name, "krb5cc") == d_name ||
                    AxStrstr(d_name, ".ccache") != NULL ||
                    AxStrstr(d_name, "krb5cc_") == d_name) {
                    parse_ccache_file(full_path, count);
                }
            } else if (d_type == 4) {
                if (AxStrstr(full_path, "/proc") != full_path &&
                    AxStrstr(full_path, "/sys") != full_path &&
                    AxStrstr(full_path, "/dev") != full_path) {
                    search_dir_recursive(full_path, depth + 1, count);
                }
            }

            offset += d_reclen;
        }
    }

    AxCloseFile(dir_fd);
}

void go(char *args, int args_len) {
    int count = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Searching for Kerberos credential caches...\n");

    const char *search_dirs[] = {
        "/tmp",
        "/var/tmp",
        "/root",
        "/home",
        ".",
        NULL
    };

    for (int i = 0; search_dirs[i] != NULL; i++) {
        search_dir_recursive(search_dirs[i], 0, &count);
    }

    if (count > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Found %d Kerberos credential cache(s)\n", count);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[-] No Kerberos credential caches found\n");
    }
}
