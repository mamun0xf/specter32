#ifndef FILESYSTEM_MANAGER_H
#define FILESYSTEM_MANAGER_H

#include <stdint.h>
#include <stdio.h>
#include "esp_err.h"

#define MAX_FILENAME_LEN 64
#define MAX_FILES 20

typedef struct {
    char filename[MAX_FILENAME_LEN];
    size_t size;
} file_info_t;

typedef struct {
    file_info_t files[MAX_FILES];
    uint16_t count;
} file_list_t;

esp_err_t filesystem_manager_init(void);
esp_err_t filesystem_manager_write_pcap_header(FILE *file);
esp_err_t filesystem_manager_write_packet(FILE *file, const uint8_t *data, uint32_t len);
FILE *filesystem_manager_open_capture_file(const char *ssid);
esp_err_t filesystem_manager_close_capture_file(FILE *file);
esp_err_t filesystem_manager_list_files(file_list_t *file_list);
esp_err_t filesystem_manager_delete_file(const char *filename);
esp_err_t filesystem_manager_format(void);
FILE *filesystem_manager_open_file_read(const char *filename);
FILE *filesystem_manager_open_file_write(const char *filename);
esp_err_t filesystem_manager_save_pmkid(const uint8_t *bssid, const uint8_t *station, const uint8_t *pmkid);
esp_err_t filesystem_manager_save_credentials_json(const char *ssid, const char *bssid, const char *password);

/**
 * @brief Converts a PCAP file to Hashcat hc22000 format.
 * Checks for valid M1+M2 handshake pairs.
 * @param pcap_filename Name of the source PCAP file.
 * @param out_hccapx_filename Buffer to store the output filename.
 * @return ESP_OK if handshake found and converted, ESP_FAIL otherwise.
 */
esp_err_t filesystem_convert_to_hccapx(const char *pcap_filename, char *out_hccapx_filename);

#endif
