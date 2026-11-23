#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <dirent.h>
#include <unistd.h>
#include "esp_log.h"
#include "esp_littlefs.h"
#include "filesystem_manager.h"
#include "cJSON.h"
#include <time.h>
#include <arpa/inet.h>

static const char *TAG = "FILESYSTEM_MANAGER";
static const char *BASE_PATH = "/littlefs";

typedef struct {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_hdr_t;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcaprec_hdr_t;

typedef struct {
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
} __attribute__((packed)) wifi_mac_header_t;

typedef struct {
    uint8_t  version;
    uint8_t  type;
    uint16_t length;
    uint8_t  key_desc_type;
    uint16_t key_info;
    uint16_t key_len;
    uint8_t  replay_counter[8];
    uint8_t  key_nonce[32];
    uint8_t  key_iv[16];
    uint8_t  key_rsc[8];
    uint8_t  key_id[8];
    uint8_t  key_mic[16];
    uint16_t key_data_len;
    uint8_t  key_data[];
} __attribute__((packed)) eapol_key_packet_t;

#define WPA_KEY_INFO_MIC      (1 << 8)
#define WPA_KEY_INFO_ACK      (1 << 7)

static void bytes_to_hex(char *out, const uint8_t *in, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sprintf(out + (i * 2), "%02x", in[i]);
    }
}

static eapol_key_packet_t* parse_eapol_key_smart(uint8_t *buf, uint32_t len) {
    if (len < 40) return NULL;

    uint8_t eapol_snap[] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};

    for (int i = 0; i < len - 16; i++) {
        if (memcmp(buf + i, eapol_snap, 8) == 0) {

            if (buf[i + 9] == 3) {

                return (eapol_key_packet_t*)(buf + i + 8);
            }
        }
    }
    return NULL;
}

esp_err_t filesystem_manager_init(void)
{
    esp_vfs_littlefs_conf_t conf = {
        .base_path = BASE_PATH,
        .partition_label = "storage",
        .format_if_mount_failed = true,
        .dont_mount = false
    };
    esp_err_t ret = esp_vfs_littlefs_register(&conf);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize LittleFS (%s)", esp_err_to_name(ret));
        return ret;
    }
    ESP_LOGI(TAG, "Filesystem initialized");
    return ESP_OK;
}

esp_err_t filesystem_manager_write_pcap_header(FILE *file)
{
    if (!file) return ESP_ERR_INVALID_ARG;
    pcap_hdr_t pcap_header = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = 105
    };
    fwrite(&pcap_header, sizeof(pcap_header), 1, file);
    fflush(file);
    return ESP_OK;
}

esp_err_t filesystem_manager_write_packet(FILE *file, const uint8_t *data, uint32_t len)
{
    if (!file || !data || len == 0) return ESP_ERR_INVALID_ARG;
    struct timeval tv;
    gettimeofday(&tv, NULL);

    pcaprec_hdr_t packet_header = {
        .ts_sec = tv.tv_sec,
        .ts_usec = tv.tv_usec,
        .incl_len = len,
        .orig_len = len
    };
    fwrite(&packet_header, sizeof(packet_header), 1, file);
    fwrite(data, 1, len, file);
    fflush(file);
    return ESP_OK;
}

FILE *filesystem_manager_open_capture_file(const char *ssid)
{
    if (!ssid) return NULL;
    char filename[128], safe_ssid[64];
    int j = 0;
    for (int i = 0; i < strlen(ssid) && j < 63; i++) {
        char c = ssid[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
            safe_ssid[j++] = c;
        } else if (c == ' ') {
            safe_ssid[j++] = '_';
        }
    }
    safe_ssid[j] = '\0';
    if (strlen(safe_ssid) == 0) strcpy(safe_ssid, "unknown");

    snprintf(filename, sizeof(filename), "%s/%s.pcap", BASE_PATH, safe_ssid);
    FILE *file = fopen(filename, "ab");
    if (file) ESP_LOGI(TAG, "Opened capture file: %s", filename);
    return file;
}

esp_err_t filesystem_manager_close_capture_file(FILE *file)
{
    if (!file) return ESP_ERR_INVALID_ARG;
    fclose(file);
    return ESP_OK;
}

esp_err_t filesystem_manager_list_files(file_list_t *file_list)
{
    if (!file_list) return ESP_ERR_INVALID_ARG;
    DIR *dir = opendir(BASE_PATH);
    if (!dir) return ESP_FAIL;

    file_list->count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && file_list->count < MAX_FILES) {
        if (entry->d_type == DT_REG && entry->d_name[0] != '.') {
            snprintf(file_list->files[file_list->count].filename, MAX_FILENAME_LEN, "%.*s", MAX_FILENAME_LEN - 1, entry->d_name);
            char full_path[512];
            snprintf(full_path, sizeof(full_path), "%s/%s", BASE_PATH, entry->d_name);
            struct stat st;
            if (stat(full_path, &st) == 0) {
                file_list->files[file_list->count].size = st.st_size;
            }
            file_list->count++;
        }
    }
    closedir(dir);
    return ESP_OK;
}

esp_err_t filesystem_manager_delete_file(const char *filename)
{
    if (!filename) return ESP_ERR_INVALID_ARG;
    char full_path[512];
    snprintf(full_path, sizeof(full_path), "%s/%s", BASE_PATH, filename);
    if (unlink(full_path) != 0) return ESP_FAIL;
    return ESP_OK;
}

esp_err_t filesystem_manager_format(void)
{
    ESP_LOGW(TAG, "Formatting filesystem...");
    return esp_littlefs_format("storage");
}

FILE *filesystem_manager_open_file_read(const char *filename)
{
    if (!filename) return NULL;
    char full_path[512];
    snprintf(full_path, sizeof(full_path), "%s/%s", BASE_PATH, filename);
    return fopen(full_path, "rb");
}

FILE *filesystem_manager_open_file_write(const char *filename)
{
    if (!filename) return NULL;
    char full_path[512];
    snprintf(full_path, sizeof(full_path), "%s/%s", BASE_PATH, filename);
    return fopen(full_path, "wb");
}

esp_err_t filesystem_manager_save_credentials_json(const char *ssid, const char *bssid, const char *password)
{
    char filepath[128];
    snprintf(filepath, sizeof(filepath), "%s/credentials.json", BASE_PATH);
    FILE *f = fopen(filepath, "a");
    if (!f) return ESP_FAIL;

    cJSON *root = cJSON_CreateObject();
    if (root) {
        time_t now = time(NULL);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));

        cJSON_AddStringToObject(root, "timestamp", time_str);
        cJSON_AddStringToObject(root, "ssid", ssid);
        cJSON_AddStringToObject(root, "bssid", bssid);
        cJSON_AddStringToObject(root, "password", password);
        char *json_string = cJSON_PrintUnformatted(root);
        if (json_string) {
            fprintf(f, "%s\n", json_string);
            free(json_string);
        }
        cJSON_Delete(root);
    }
    fclose(f);
    return ESP_OK;
}

esp_err_t filesystem_convert_to_hccapx(const char *pcap_filename, char *out_hccapx_filename) {
    char full_pcap_path[128];
    char full_hccapx_path[128];
    snprintf(full_pcap_path, sizeof(full_pcap_path), "/littlefs/%s", pcap_filename);

    strcpy(out_hccapx_filename, pcap_filename);
    char *dot = strrchr(out_hccapx_filename, '.');
    if(dot) strcpy(dot, ".hc22000");
    else strcat(out_hccapx_filename, ".hc22000");

    snprintf(full_hccapx_path, sizeof(full_hccapx_path), "/littlefs/%s", out_hccapx_filename);

    FILE *fp_in = fopen(full_pcap_path, "rb");
    if (!fp_in) {
        ESP_LOGE(TAG, "Cannot open PCAP: %s", full_pcap_path);
        return ESP_FAIL;
    }

    FILE *fp_out = fopen(full_hccapx_path, "w");
    if (!fp_out) { fclose(fp_in); return ESP_FAIL; }

    fseek(fp_in, 24, SEEK_SET);

    uint8_t pcap_rec_hdr[16];
    uint8_t buffer[2048];

    uint8_t mac_ap[6] = {0};
    uint8_t mac_sta[6] = {0};
    uint8_t anonce[32] = {0};
    uint8_t essid[32] = {0};
    uint8_t essid_len = 0;

    bool has_m1 = false;
    bool found_handshake = false;

    char filename_only[64];
    strncpy(filename_only, pcap_filename, sizeof(filename_only)-1);
    char *ext = strrchr(filename_only, '.');
    if(ext) *ext = '\0';

    size_t fn_len = strlen(filename_only);
    if(fn_len > 32) fn_len = 32;
    memcpy(essid, filename_only, fn_len);
    essid_len = fn_len;

    ESP_LOGI(TAG, "Converting %s. Default SSID: %s", pcap_filename, filename_only);

    while(fread(pcap_rec_hdr, 1, 16, fp_in) == 16) {
        uint32_t incl_len = *(uint32_t*)(pcap_rec_hdr + 8);
        if(incl_len > sizeof(buffer) || incl_len == 0) {
            fseek(fp_in, incl_len, SEEK_CUR);
            continue;
        }

        if (fread(buffer, 1, incl_len, fp_in) != incl_len) break;

        if ((buffer[0] & 0xFC) == 0x80) {

             if (incl_len > 36) {
                uint8_t *ptr = buffer + 36;
                uint8_t *end = buffer + incl_len;
                while (ptr + 2 < end) {
                    uint8_t tag_num = ptr[0];
                    uint8_t tag_len = ptr[1];
                    if (ptr + 2 + tag_len > end) break;

                    if (tag_num == 0 && tag_len > 0 && tag_len <= 32) {
                        memcpy(essid, ptr + 2, tag_len);
                        essid_len = tag_len;

                        break;
                    }
                    ptr += 2 + tag_len;
                }
            }
        }

        eapol_key_packet_t *key = parse_eapol_key_smart(buffer, incl_len);
        if (key) {
            uint16_t key_info = ntohs(key->key_info);
            wifi_mac_header_t *mac_hdr = (wifi_mac_header_t *)buffer;

            bool is_pairwise = (key_info & (1<<3));
            bool has_mic = (key_info & WPA_KEY_INFO_MIC);

            if (is_pairwise && !has_mic) {
                memcpy(mac_ap, mac_hdr->addr2, 6);
                memcpy(mac_sta, mac_hdr->addr1, 6);
                memcpy(anonce, key->key_nonce, 32);
                has_m1 = true;

                uint16_t key_data_len = ntohs(key->key_data_len);
                if (key_data_len > 0) {
                    uint8_t *kd = key->key_data;
                    int k_off = 0;
                    while (k_off < key_data_len) {
                        uint8_t tag = kd[k_off];
                        uint8_t tlen = kd[k_off+1];
                        if (tag == 0x30) {

                            int rsn_ptr = 2 + 2 + 4;
                            if (k_off + rsn_ptr + 2 > key_data_len) break;
                            uint16_t pc_cnt = kd[k_off+rsn_ptr] | (kd[k_off+rsn_ptr+1]<<8);
                            rsn_ptr += 2 + (pc_cnt * 4);

                            if (k_off + rsn_ptr + 2 > key_data_len) break;
                            uint16_t akm_cnt = kd[k_off+rsn_ptr] | (kd[k_off+rsn_ptr+1]<<8);
                            rsn_ptr += 2 + (akm_cnt * 4) + 2;

                            if (k_off + rsn_ptr + 2 <= key_data_len) {
                                uint16_t pmkid_cnt = kd[k_off+rsn_ptr] | (kd[k_off+rsn_ptr+1]<<8);
                                if (pmkid_cnt > 0) {

                                    uint8_t *pmkid = &kd[k_off + rsn_ptr + 2];

                                    char spmkid[33], sap[13], ssta[13], sessid[65];
                                    bytes_to_hex(spmkid, pmkid, 16);
                                    bytes_to_hex(sap, mac_ap, 6);
                                    bytes_to_hex(ssta, mac_sta, 6);
                                    bytes_to_hex(sessid, essid, essid_len);

                                    fprintf(fp_out, "WPA*01*%s*%s*%s*%s***\n", spmkid, sap, ssta, sessid);
                                    found_handshake = true;
                                    ESP_LOGI(TAG, "PMKID Found & Converted!");
                                }
                            }
                        }
                        k_off += 2 + tlen;
                    }
                }

            }

            else if (is_pairwise && has_mic && has_m1) {

                if(memcmp(mac_hdr->addr1, mac_ap, 6) == 0) {
                    memcpy(mac_sta, mac_hdr->addr2, 6);

                    uint8_t *eapol_start = (uint8_t*)key;
                    uint16_t eapol_len = (key->length) + 4;

                    eapol_len = (ntohs(key->length)) + 4;

                    if((uint8_t*)eapol_start + eapol_len <= buffer + incl_len) {
                        uint8_t temp_eapol[512];
                        if(eapol_len > 512) eapol_len = 512;
                        memcpy(temp_eapol, eapol_start, eapol_len);

                        memset(temp_eapol + 81, 0, 16);

                        char smic[33], sap[13], ssta[13], san[65], ses[65], seapol[1025];
                        bytes_to_hex(smic, key->key_mic, 16);
                        bytes_to_hex(sap, mac_ap, 6);
                        bytes_to_hex(ssta, mac_sta, 6);
                        bytes_to_hex(san, anonce, 32);
                        bytes_to_hex(ses, essid, essid_len);
                        bytes_to_hex(seapol, temp_eapol, eapol_len);

                        fprintf(fp_out, "WPA*02*%s*%s*%s*%s*%s*%s\n",
                                smic, sap, ssta, ses, san, seapol);

                        found_handshake = true;
                        has_m1 = false;
                        ESP_LOGI(TAG, "Handshake converted: %s", out_hccapx_filename);
                    }
                }
            }
        }
    }

    fclose(fp_in);
    fclose(fp_out);

    if (!found_handshake) {
        unlink(full_hccapx_path);
        ESP_LOGW(TAG, "No handshake found in %s", pcap_filename);
        return ESP_FAIL;
    }
    return ESP_OK;
}
