#ifndef ATTACK_MANAGER_H
#define ATTACK_MANAGER_H

#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

#define MAX_CLIENTS 20

typedef enum {
    ATTACK_STATE_IDLE,
    ATTACK_STATE_DEAUTH_CONTINUOUS,
    ATTACK_STATE_CAPTURE_CREDENTIALS,
    ATTACK_STATE_EVIL_TWIN,
    ATTACK_STATE_BEACON_FLOOD,
    ATTACK_STATE_CLIENT_SCAN,
    ATTACK_STATE_PMKID_CAPTURE,
    ATTACK_STATE_AUTO_HUNT
} attack_state_t;

typedef enum {
    BEACON_MODE_CUSTOM = 0,
    BEACON_MODE_CLONE = 1,
    BEACON_MODE_DATABASE = 2
} beacon_flood_mode_t;

typedef struct {
    uint8_t mac[6];
} client_mac_t;

typedef struct {
    client_mac_t clients[MAX_CLIENTS];
    int count;
} client_list_t;

esp_err_t attack_manager_init(void);

esp_err_t attack_manager_start_continuous_deauth(void);
esp_err_t attack_manager_stop_continuous_deauth(void);

esp_err_t attack_manager_start_capture(void);
esp_err_t attack_manager_stop_capture(void);

esp_err_t attack_manager_start_beacon_flood(beacon_flood_mode_t mode, const char *ssid_val, uint16_t amount);
esp_err_t attack_manager_stop_beacon_flood(void);

esp_err_t attack_manager_start_client_scan(void);
esp_err_t attack_manager_get_client_scan_results(client_list_t *list);

esp_err_t attack_manager_start_pmkid_capture(void);
esp_err_t attack_manager_stop_pmkid_capture(void);

esp_err_t attack_manager_start_auto_hunt(int pmkid_time, int handshake_time);
esp_err_t attack_manager_stop_auto_hunt(void);

attack_state_t attack_manager_get_state(void);
void attack_manager_set_state(attack_state_t new_state);

#endif
