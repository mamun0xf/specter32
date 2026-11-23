#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include <stdint.h>
#include "esp_wifi.h"
#include "esp_err.h"

typedef void (*packet_callback_t)(void *buf, wifi_promiscuous_pkt_type_t type);

esp_err_t packet_handler_init(void);

esp_err_t packet_handler_start_monitor(uint8_t channel, packet_callback_t callback);
esp_err_t packet_handler_stop_monitor(void);

esp_err_t packet_handler_start_deauth(uint8_t *dest_mac, uint8_t *ap_mac);
esp_err_t packet_handler_stop_deauth(void);

esp_err_t packet_handler_send_deauth_frame(uint8_t *dest_mac, uint8_t *ap_mac);

esp_err_t packet_handler_set_channel(uint8_t channel);

/**
 * @brief Sends a single beacon frame with the specified SSID and a RANDOM BSSID.
 * (Legacy wrapper for backward compatibility)
 * @param ssid The SSID string to broadcast.
 */
void packet_handler_send_beacon(const char *ssid);

/**
 * @brief Sends a beacon frame with EXPLICIT parameters.
 * Used for stable beacon flooding where MACs are pre-generated.
 * * @param ssid The SSID string.
 * @param bssid Pointer to 6-byte MAC address to use as BSSID/Source.
 * @param channel The channel number to include in the beacon DS Parameter set.
 */
void packet_handler_send_beacon_raw(const char *ssid, uint8_t *bssid, uint8_t channel);

#endif
