#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_netif.h"

#include "wifi_manager.h"
#include "attack_manager.h"
#include "web_server.h"
#include "packet_handler.h"
#include "filesystem_manager.h"
#include "evil_twin_manager.h"

static const char *TAG = "MAIN";

void app_main(void)
{

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    vTaskDelay(pdMS_TO_TICKS(500));

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_log_level_set("wifi", ESP_LOG_ERROR);

    ESP_LOGI(TAG, "===== Specter32 — WiFi Security Auditor =====");
    ESP_LOGI(TAG, "Starting system initialization...");

    ESP_LOGI(TAG, "Initializing filesystem...");
    filesystem_manager_init();

    ESP_LOGI(TAG, "Initializing WiFi manager...");
    wifi_manager_init();

    ESP_LOGI(TAG, "Initializing packet handler...");
    packet_handler_init();

    ESP_LOGI(TAG, "Initializing attack manager...");
    attack_manager_init();

    ESP_LOGI(TAG, "Initializing Evil Twin manager...");
    evil_twin_manager_init();

    ESP_LOGI(TAG, "Starting WiFi Access Point...");
    wifi_manager_start_softap();

    ESP_LOGI(TAG, "Starting web server...");
    web_server_start();

    ESP_LOGI(TAG, "===== System Ready =====");
    ESP_LOGI(TAG, "Connect to WiFi: %s", SOFTAP_SSID);
    ESP_LOGI(TAG, "Access web interface: http://192.168.4.1");
    ESP_LOGI(TAG, "=======================================");

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}
