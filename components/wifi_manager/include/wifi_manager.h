#ifndef WIFI_MANAGER_H
#define WIFI_MANAGER_H

#include "esp_wifi.h"
#include <stdbool.h>

#define MAX_SCAN_RESULTS 20
#define SOFTAP_SSID "Specter32"
#define SOFTAP_PASS "Specter32#esp"
#define SOFTAP_MAX_STA_CONN 4

typedef struct {
    char ssid[33];
    char bssid[18];
    int8_t rssi;
    uint8_t channel;
    wifi_auth_mode_t authmode;
} wifi_scan_result_t;

typedef struct {
    wifi_scan_result_t results[MAX_SCAN_RESULTS];
    uint16_t count;
} wifi_scan_data_t;

esp_err_t wifi_manager_init(void);
esp_err_t wifi_manager_start_softap(void);
esp_err_t wifi_manager_stop_softap(void);

/**
 * @brief Standard network scan using Active Scanning for better discovery.
 */
esp_err_t wifi_manager_scan_networks(wifi_scan_data_t *scan_data);

/**
 * @brief Advanced scan specifically for Attack Manager (Clone Mode).
 * Currently wraps wifi_manager_scan_networks but ensures Active Scan parameters.
 */
void wifi_manager_scan_networks_advanced(wifi_scan_data_t *scan_data_out);

esp_err_t wifi_manager_set_target(const char *ssid, const char *bssid);
esp_err_t wifi_manager_get_target(char *ssid, char *bssid);
esp_err_t wifi_manager_get_target_channel(uint8_t *channel);
bool wifi_manager_has_target(void);
esp_err_t wifi_manager_change_channel(uint8_t channel);

/**
 * @brief Starts an open Wi-Fi AP mimicking the target.
 * Uses APSTA mode to allow simultaneous station connection.
 * Forces radio to tune to target channel before starting.
 */
esp_err_t wifi_manager_start_evil_twin_ap(void);

/**
 * @brief Stops Evil Twin and restores management AP.
 */
esp_err_t wifi_manager_restore_softap(void);
esp_err_t wifi_manager_restore_softap_channel(void);

/**
 * @brief Attempts to connect the STA interface to the real target AP.
 * Used to verify the captured password live.
 * @param password The password submitted by the victim.
 */
esp_err_t wifi_manager_connect_sta(const char *password);

/**
 * @brief Disconnects the STA interface.
 */
esp_err_t wifi_manager_disconnect_sta(void);

/**
 * @brief Connects to a target AP and enables NAPT (Network Address Port Translation).
 * This turns the ESP32 into a travel router/repeater.
 * @param ssid Target SSID
 * @param password Target Password
 */
esp_err_t wifi_manager_connect_repeater(const char *ssid, const char *password);
esp_err_t wifi_manager_disconnect_repeater(void);
bool wifi_manager_is_repeater_active(void);
char* wifi_manager_get_repeater_status(void);

#endif
